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
local lfs = require("libs/libkoreader-lfs")
local logger = require("logger")
local util = require("util")
local _ = require("gettext")
local T = require("ffi/util").template

ffi.cdef[[
    int lcp_init(void);
    int lcp_is_encrypted(const char* epub_path);
    int lcp_decrypt_epub(const char* epub_path, const char* output_path, const char* passphrase);
    const char* lcp_get_error(void);
]]

local LcpReader = WidgetContainer:extend{
    name = "lcpreader",
    fullname = _("LCP Reader"),
    lcp_lib = nil,
}

function LcpReader:init()
    -- This plugin is loaded by both FileManager and ReaderUI.
    -- Only set up file interception in FileManager context.
    if self.ui.document then return end

    self.passphrase_cache = G_reader_settings:readSetting("lcp_passphrase_cache", {})

    self:registerDocumentRegistryAuxProvider()
    self:patchFileManagerOpenFile()
end

function LcpReader:registerDocumentRegistryAuxProvider()
    DocumentRegistry:addAuxProvider({
        provider_name = self.fullname,
        provider = self.name,
        order = 10,
        disable_file = true,
        disable_type = false,
    })
end

function LcpReader:patchFileManagerOpenFile()
    local FileManager = require("apps/filemanager/filemanager")

    if FileManager._original_openFile then return end
    FileManager._original_openFile = FileManager.openFile

    local self_ref = self

    function FileManager:openFile(file, provider, doc_caller_callback, aux_caller_callback)
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
        return FileManager._original_openFile(self, file, provider, doc_caller_callback, aux_caller_callback)
    end
end

function LcpReader:loadLibrary()
    if self.lcp_lib then return self.lcp_lib end

    local ok, lib = pcall(ffi.loadlib, "readium_lcp")
    if ok then
        lib.lcp_init()
        self.lcp_lib = lib
        return lib
    end

    local extension = ffi.os == "OSX" and ".dylib" or ".so"
    local paths = {
        "plugins/lcpreader.koplugin/libs/libreadium_lcp" .. extension,
        "libs/libreadium_lcp" .. extension,
    }

    for _, path in ipairs(paths) do
        ok, lib = pcall(ffi.load, path)
        if ok then
            lib.lcp_init()
            self.lcp_lib = lib
            return lib
        end
    end

    return nil
end

function LcpReader:isLcpEncrypted(file)
    local lib = self:loadLibrary()
    if not lib then return false end

    local result = lib.lcp_is_encrypted(file)
    if result == 1 then
        return true
    elseif result == 0 then
        return false
    else
        local err = lib.lcp_get_error()
        return false, err ~= nil and ffi.string(err) or "Unknown error"
    end
end

function LcpReader:getTempPath(original_path)
    local _, filename = util.splitFilePathName(original_path)
    local name_without_ext = filename:match("(.+)%..+$") or filename
    return "/tmp/" .. name_without_ext .. "_lcp.epub"
end

function LcpReader:decryptEpub(file, passphrase, output_path)
    local lib = self:loadLibrary()
    if not lib then return false, "LCP library not found" end

    local result = lib.lcp_decrypt_epub(file, output_path, passphrase)
    if result == 0 then
        return true
    elseif result == 1 then
        return false, "Incorrect passphrase"
    elseif result == 2 then
        return false, "File is not LCP encrypted"
    else
        local err = lib.lcp_get_error()
        return false, err ~= nil and ffi.string(err) or "Unknown error"
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

    local is_encrypted, err = self:isLcpEncrypted(file)
    if err then
        UIManager:show(InfoMessage:new{
            text = T(_("Error checking LCP encryption: %1"), err),
            timeout = 5,
        })
        return
    end

    if not is_encrypted then
        local provider = DocumentRegistry:getProvider(file)
        if provider then
            local ReaderUI = require("apps/reader/readerui")
            ReaderUI:showReader(file, provider)
        end
        return
    end

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

    -- Reuse existing decrypted file if it's still in /tmp
    if lfs.attributes(output_path, "mode") ~= "file" then
        local busy = InfoMessage:new{ text = _("Decrypting...") }
        UIManager:show(busy)
        UIManager:forceRePaint()

        local success, err = self:decryptEpub(file, passphrase, output_path)
        UIManager:close(busy)

        if not success then
            if err == "Incorrect passphrase" then
                self.passphrase_cache[file] = nil
                G_reader_settings:saveSetting("lcp_passphrase_cache", self.passphrase_cache)
                self:promptForPassphrase(file, true)
            else
                UIManager:show(InfoMessage:new{
                    text = T(_("Decryption failed: %1"), err),
                    timeout = 5,
                })
            end
            return
        end
    end

    self.passphrase_cache[file] = passphrase
    G_reader_settings:saveSetting("lcp_passphrase_cache", self.passphrase_cache)

    -- Store mapping so onCloseDocument can redirect the file browser
    local map = G_reader_settings:readSetting("lcp_decrypted_map", {})
    map[output_path] = file
    G_reader_settings:saveSetting("lcp_decrypted_map", map)

    local provider = DocumentRegistry:getProvider(output_path)
    if provider then
        local ReaderUI = require("apps/reader/readerui")
        ReaderUI:showReader(output_path, provider, true)
    end
end

function LcpReader:isFileTypeSupported(file)
    return util.getFileNameSuffix(file):lower() == "epub"
end

function LcpReader:onCloseDocument()
    local doc_path = self.ui and self.ui.document and self.ui.document.file
    if not doc_path then return end

    local map = G_reader_settings:readSetting("lcp_decrypted_map", {})
    local original = map[doc_path]
    if original then
        require("readhistory"):removeItemByPath(doc_path)
        local original_dir = util.splitFilePathName(original)
        self.ui:setLastDirForFileBrowser(original_dir)
        map[doc_path] = nil
        G_reader_settings:saveSetting("lcp_decrypted_map", map)
    end
end

function LcpReader:cleanupTempFiles()
    local p = io.popen('ls /tmp')
    if not p then return end
    for name in p:lines() do
        if name:match("_lcp%.epub$") then
            logger.dbg("LcpReader: removing", name)
            os.remove("/tmp/" .. name)
        end
    end
    p:close()
end

function LcpReader:onSuspend()
    self:cleanupTempFiles()
end

function LcpReader:onExit()
    self:cleanupTempFiles()
end

return LcpReader
