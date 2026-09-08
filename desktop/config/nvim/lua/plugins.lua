-- WardOS — the plugin hook. init.lua requires this module last; it ships empty so
-- Neovim starts offline. To use lazy.nvim, treesitter and LSP, uncomment the block
-- below (the clone happens once, from GitHub, when you first start Neovim online)
-- and add specs to the table. `wardos-refresh nvim` keeps a backup of this file.

-- local lazypath = vim.fn.stdpath("data") .. "/lazy/lazy.nvim"
-- if not vim.uv.fs_stat(lazypath) then
--   vim.fn.system({ "git", "clone", "--filter=blob:none", "--branch=stable",
--     "https://github.com/folke/lazy.nvim.git", lazypath })
-- end
-- vim.opt.rtp:prepend(lazypath)
-- require("lazy").setup({
--   { "nvim-treesitter/nvim-treesitter", build = ":TSUpdate" },
--   { "neovim/nvim-lspconfig" },
-- }, { ui = { border = "single" } })

return {}
