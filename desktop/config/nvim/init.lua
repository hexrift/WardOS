-- WardOS — Neovim (docs/desktop.md §Parity: "neovim with a WardOS config and
-- per-theme colours").
--
-- Self-contained: no plugin manager is downloaded at first start (the image has no
-- `curl | sh`, and an editor must open offline). Sensible options, Space as leader,
-- a few keymaps, and the theme's colours from the fragment wardos-theme renders
-- (~/.config/wardos/theme/current/nvim.lua, a module returning highlight groups).
-- Plugins, treesitter and LSP are the user's: lua/plugins.lua is required when it
-- exists and is the place to bootstrap lazy.nvim or anything else (see the shipped
-- stub next to this file).

vim.g.mapleader = " "
vim.g.maplocalleader = " "

-- Options ---------------------------------------------------------------------
local o = vim.opt
o.number = true
o.relativenumber = false
o.signcolumn = "yes"
o.cursorline = true
o.wrap = false
o.scrolloff = 6
o.sidescrolloff = 8
o.expandtab = true
o.shiftwidth = 2
o.tabstop = 2
o.softtabstop = 2
o.smartindent = true
o.ignorecase = true
o.smartcase = true
o.incsearch = true
o.hlsearch = true
o.splitbelow = true
o.splitright = true
o.termguicolors = true
o.mouse = "a"
o.clipboard = "unnamedplus"
o.undofile = true
o.swapfile = false
o.updatetime = 250
o.timeoutlen = 400
o.completeopt = { "menuone", "noselect" }
o.list = true
o.listchars = { tab = "» ", trail = "·", nbsp = "␣" }
o.showmode = false
o.laststatus = 3
o.fillchars = { eob = " ", vert = "│", horiz = "─" }

-- Keymaps ---------------------------------------------------------------------
local map = vim.keymap.set
map("n", "<Esc>", "<cmd>nohlsearch<CR>", { desc = "Clear search" })
map("n", "<leader>w", "<cmd>write<CR>", { desc = "Write" })
map("n", "<leader>q", "<cmd>quit<CR>", { desc = "Quit" })
map("n", "<leader>e", "<cmd>Explore<CR>", { desc = "Files" })
map("n", "<C-h>", "<C-w>h", { desc = "Window left" })
map("n", "<C-j>", "<C-w>j", { desc = "Window down" })
map("n", "<C-k>", "<C-w>k", { desc = "Window up" })
map("n", "<C-l>", "<C-w>l", { desc = "Window right" })
map("n", "<S-h>", "<cmd>bprevious<CR>", { desc = "Previous buffer" })
map("n", "<S-l>", "<cmd>bnext<CR>", { desc = "Next buffer" })
map("v", "<", "<gv", { desc = "Outdent" })
map("v", ">", ">gv", { desc = "Indent" })
map("v", "J", ":m '>+1<CR>gv=gv", { desc = "Move lines down" })
map("v", "K", ":m '<-2<CR>gv=gv", { desc = "Move lines up" })
map("n", "<leader>d", vim.diagnostic.open_float, { desc = "Diagnostic" })

-- Theme -----------------------------------------------------------------------
-- The fragment returns { Normal = { fg = "#…", bg = "#…" }, … } for nvim_set_hl.
-- Applied at start and again on SIGUSR1, which `wardos-theme set` sends to every
-- running nvim, so a theme change reaches open editors without a restart.
local function apply_theme()
  local fragment = vim.fn.expand("~/.config/wardos/theme/current/nvim.lua")
  if vim.fn.filereadable(fragment) == 0 then
    vim.cmd.colorscheme("default")
    vim.opt.background = "dark"
    return
  end
  local ok, groups = pcall(dofile, fragment)
  if not ok or type(groups) ~= "table" then
    vim.notify("wardos theme: " .. tostring(groups), vim.log.levels.WARN)
    return
  end
  vim.cmd("highlight clear")
  vim.g.colors_name = "wardos"
  for name, spec in pairs(groups) do
    vim.api.nvim_set_hl(0, name, spec)
  end
end
apply_theme()
vim.api.nvim_create_autocmd("Signal", { pattern = "SIGUSR1", callback = apply_theme })

-- Files -------------------------------------------------------------------------
vim.api.nvim_create_autocmd("TextYankPost", {
  callback = function() vim.highlight.on_yank({ timeout = 120 }) end,
})
vim.api.nvim_create_autocmd("BufReadPost", {
  callback = function()
    local mark = vim.api.nvim_buf_get_mark(0, '"')
    if mark[1] > 0 and mark[1] <= vim.api.nvim_buf_line_count(0) then
      pcall(vim.api.nvim_win_set_cursor, 0, mark)
    end
  end,
})

-- Plugins: the user's hook (lua/plugins.lua). Absent by default beyond the stub.
pcall(require, "plugins")
