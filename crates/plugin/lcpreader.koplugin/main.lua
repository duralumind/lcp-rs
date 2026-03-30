--[[--
LCP Reader Plugin - Decrypt and read Readium LCP protected EPUBs.

This plugin intercepts EPUB file opens and checks if they are LCP encrypted.
If encrypted, it prompts for the user's passphrase, decrypts to a temporary file,
and opens the decrypted content with the standard EPUB reader.

@module koplugin.LcpReader
--]]

local DocumentRegistry = require("document/documentregistry")
local InfoMessage = require("ui/widget/infomessage")
local InputDialog = require("ui/widget/inputdialog")
local UIManager = require("ui/uimanager")
local WidgetContainer = require("ui/widget/container/widgetcontainer")
local ffi = require("ffi")
local logger = require("logger")
local util = require("util")
local _ = require("gettext")
local T = require("ffi/util").template

-- FFI declarations for the LCP library
ffi.cdef[[
    int lcp_init(void);
    int lcp_is_encrypted(const char* epub_path);
    int lcp_decrypt_epub(const char* epub_path, const char* output_path, const char* passphrase);
    const char* lcp_get_error(void);
]]

local LcpReader = WidgetContainer:extend{
    name = "lcpreader",
    fullname = _("LCP Reader"),
    -- Cache for passphrases (keyed by file path)
    passphrase_cache = {},
    -- The LCP library handle (loaded lazily)
    lcp_lib = nil,
}

function LcpReader:init()
    self:registerDocumentRegistryAuxProvider()  -- Keep for "Open with..." fallback
    self:patchFileManagerOpenFile()              -- Auto-detection

    -- Load cached passphrases from persistent storage
    self.passphrase_cache = G_reader_settings:readSetting("lcp_passphrase_cache", {})
end

function LcpReader:registerDocumentRegistryAuxProvider()
    DocumentRegistry:addAuxProvider({
        provider_name = self.fullname,
        provider = self.name,
        order = 10, -- Higher priority in OpenWith dialog
        disable_file = true,
        disable_type = false,
    })
end

function LcpReader:patchFileManagerOpenFile()
    local FileManager = require("apps/filemanager/filemanager")

    -- Guard against double-patching (e.g., plugin reloaded)
    if FileManager._original_openFile then
        return
    end
    FileManager._original_openFile = FileManager.openFile

    local self_ref = self

    -- Replace with wrapper that checks for LCP first
    function FileManager:openFile(file, provider, doc_caller_callback, aux_caller_callback)
        -- Only intercept if no provider specified (normal file tap)
        if not provider then
            local suffix = util.getFileNameSuffix(file)
            if suffix and suffix:lower() == "epub" then
                local is_encrypted = self_ref:isLcpEncrypted(file)
                if is_encrypted then
                    logger.dbg("LcpReader: Auto-detected LCP encrypted file:", file)
                    self_ref:openFile(file)
                    return
                end
            end
        end

        -- Call original function for everything else
        return FileManager._original_openFile(self, file, provider, doc_caller_callback, aux_caller_callback)
    end

    logger.info("LcpReader: Patched FileManager:openFile() for auto-detection")
end

function LcpReader:loadLibrary()
    if self.lcp_lib then
        return self.lcp_lib
    end

    logger.dbg("LcpReader: attempting to load library")

    -- Use KOReader's ffi.loadlib which handles path resolution correctly
    -- Library should be in libs/libreadium_lcp.so (or .dylib on macOS)
    local ok, lib = pcall(ffi.loadlib, "readium_lcp")
    if ok then
        logger.info("LcpReader: successfully loaded library via ffi.loadlib")
        local init_result = lib.lcp_init()
        logger.info("LcpReader: lcp_init returned:", init_result)
        self.lcp_lib = lib
        return lib
    else
        logger.dbg("LcpReader: ffi.loadlib failed:", lib)
    end

    -- Fallback: try direct load (for development/emulator)
    local extension = ffi.os == "OSX" and ".dylib" or ".so"
    local paths = {
        "plugins/lcpreader.koplugin/libs/libreadium_lcp" .. extension,
        "libs/libreadium_lcp" .. extension,
    }

    local last_err
    for _, path in ipairs(paths) do
        logger.dbg("LcpReader: trying direct load from:", path)
        ok, lib = pcall(ffi.load, path)
        if ok then
            logger.info("LcpReader: loaded library from:", path)
            local init_result = lib.lcp_init()
            logger.info("LcpReader: lcp_init returned:", init_result)
            self.lcp_lib = lib
            return lib
        else
            last_err = lib
            logger.warn("LcpReader: failed to load from:", path, "error:", tostring(lib))
        end
    end

    logger.warn("LcpReader: could not load library from any location, last error:", tostring(last_err))
    return nil
end

function LcpReader:isLcpEncrypted(file)
    local lib = self:loadLibrary()
    if not lib then
        return false, "LCP library not found"
    end

    local result = lib.lcp_is_encrypted(file)
    if result == 1 then
        return true
    elseif result == 0 then
        return false
    else
        local err = lib.lcp_get_error()
        local err_str = err ~= nil and ffi.string(err) or "Unknown error"
        return false, err_str
    end
end

function LcpReader:getTempPath(original_path)
    -- Generate a temporary path for the decrypted EPUB
    local temp_dir = os.getenv("TMPDIR") or os.getenv("TMP") or "/tmp"
    local _, filename = util.splitFilePathName(original_path)
    local name_without_ext = filename:match("(.+)%..+$") or filename
    local temp_name = name_without_ext .. "_decrypted.epub"
    return temp_dir .. "/" .. temp_name
end

function LcpReader:decryptEpub(file, passphrase, output_path)
    local lib = self:loadLibrary()
    if not lib then
        return false, "LCP library not found"
    end

    local result = lib.lcp_decrypt_epub(file, output_path, passphrase)
    if result == 0 then
        return true
    elseif result == 1 then
        return false, "Incorrect passphrase"
    elseif result == 2 then
        return false, "File is not LCP encrypted"
    else
        local err = lib.lcp_get_error()
        local err_str = err ~= nil and ffi.string(err) or "Unknown error"
        return false, err_str
    end
end

function LcpReader:openFile(file)
    local lib = self:loadLibrary()
    if not lib then
        UIManager:show(InfoMessage:new{
            text = _("LCP library not found. Please install libreadium_lcp."),
            timeout = 5,
        })
        return
    end

    -- Check if it's LCP encrypted
    local is_encrypted, err = self:isLcpEncrypted(file)
    if err then
        UIManager:show(InfoMessage:new{
            text = T(_("Error checking LCP encryption: %1"), err),
            timeout = 5,
        })
        return
    end

    if not is_encrypted then
        -- Not LCP encrypted, open with default EPUB handler
        self:openWithDefaultReader(file)
        return
    end

    -- Check if we have a cached passphrase
    local cached_pass = self.passphrase_cache[file]
    if cached_pass then
        self:tryDecryptAndOpen(file, cached_pass)
    else
        self:promptForPassphrase(file)
    end
end

function LcpReader:promptForPassphrase(file, retry)
    local title = retry and _("Incorrect passphrase - try again") or _("LCP Protected Content")
    local dialog
    dialog = InputDialog:new{
        title = title,
        description = T(_("Enter your passphrase to unlock:\n%1"), select(2, util.splitFilePathName(file))),
        input_hint = _("Passphrase"),
        text_type = "password",
        buttons = {
            {
                {
                    text = _("Cancel"),
                    id = "close",
                    callback = function()
                        UIManager:close(dialog)
                    end,
                },
                {
                    text = _("Unlock"),
                    is_enter_default = true,
                    callback = function()
                        local passphrase = dialog:getInputText()
                        UIManager:close(dialog)
                        if passphrase and passphrase ~= "" then
                            self:tryDecryptAndOpen(file, passphrase)
                        end
                    end,
                },
            },
        },
    }
    UIManager:show(dialog)
    dialog:onShowKeyboard()
end

function LcpReader:tryDecryptAndOpen(file, passphrase)
    local output_path = self:getTempPath(file)

    -- Show a brief "Decrypting..." message
    local busy = InfoMessage:new{
        text = _("Decrypting..."),
    }
    UIManager:show(busy)
    UIManager:forceRePaint()

    local success, err = self:decryptEpub(file, passphrase, output_path)

    UIManager:close(busy)

    if success then
        -- Cache the passphrase for this file
        self.passphrase_cache[file] = passphrase
        -- Persist to disk
        G_reader_settings:saveSetting("lcp_passphrase_cache", self.passphrase_cache)

        -- Open the decrypted file
        self:openDecryptedFile(file, output_path)
    else
        if err == "Incorrect passphrase" then
            -- Clear cached passphrase and retry
            self.passphrase_cache[file] = nil
            G_reader_settings:saveSetting("lcp_passphrase_cache", self.passphrase_cache)
            self:promptForPassphrase(file, true)
        else
            UIManager:show(InfoMessage:new{
                text = T(_("Decryption failed: %1"), err),
                timeout = 5,
            })
        end
    end
end

function LcpReader:openDecryptedFile(original_file, decrypted_file)
    -- Get the EPUB document provider
    local provider = DocumentRegistry:getProvider(decrypted_file)
    if not provider then
        UIManager:show(InfoMessage:new{
            text = _("No document provider found for decrypted EPUB."),
            timeout = 5,
        })
        return
    end

    -- Store reference to original file for cleanup
    self.current_decrypted_file = decrypted_file
    self.current_original_file = original_file

    -- Open with ReaderUI
    local ReaderUI = require("apps/reader/readerui")
    ReaderUI:showReader(decrypted_file, provider)
end

function LcpReader:openWithDefaultReader(file)
    -- Open with the standard document provider (exclude aux providers)
    local provider = DocumentRegistry:getProvider(file)
    if provider then
        local ReaderUI = require("apps/reader/readerui")
        ReaderUI:showReader(file, provider)
    else
        UIManager:show(InfoMessage:new{
            text = _("No document provider found for this file."),
            timeout = 5,
        })
    end
end

function LcpReader:isFileTypeSupported(file)
    -- We handle EPUB files
    local suffix = util.getFileNameSuffix(file):lower()
    return suffix == "epub"
end

return LcpReader
