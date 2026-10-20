# ONLYOFFICE app for Box

The **ONLYOFFICE app for Box** allows users to **open, view, and co-edit** office files directly within [Box](https://www.box.com/) environment using [ONLYOFFICE Docs](https://www.onlyoffice.com/docs).

<p align="center">
  <a href="https://www.onlyoffice.com/office-for-box">
    <img width="800" src="https://static-site.onlyoffice.com/public/images/templates/office-for-box/documents/screenshot1@2x.png" alt="ONLYOFFICE for Box">
  </a>
</p>

## ▶️ How it works

1. Open the **three-dots menu (⋮)** → **Integrations** → **Open with ONLYOFFICE**.
2. The selected document (text, spreadsheet, presentation) opens in a full-screen ONLYOFFICE editor in a new tab.
3. Collaborate in **real time** by sharing files with other Box users.

> ✍️ **Note:** The app uses a **pre-configured ONLYOFFICE Docs Cloud tenant** — no setup or manual configuration required.

## ⚙️ Installation

You can install the ONLYOFFICE App for Box directly from the **Box App Center**:

1. Sign in to your Box account.
2. Go to [Box App Center](https://app.box.com/integrations/onlyoffice_personal/i).
3. Click **Add** to connect ONLYOFFICE.

## 📁 Supported file formats

The ONLYOFFICE App for Box supports the following file formats:

| Formats                                      | Editing behavior              | Notes                                 |
| -------------------------------------------- | ----------------------------- | ------------------------------------- |
| OOXML (DOCX, XLSX, PPTX)                     | Full editing in ONLYOFFICE    | —                                     |
| ODT, ODP, ODS, TXT, CSV, RTF, EPUB, FB2      | View-only or limited editing  | Convert to OOXML for reliable editing |
| DOC, XLS, PPT, DOT, ET, FODP, HTM, POT, etc. | View-only or convert to OOXML | Editing requires conversion           |
| PDF, DJVU, OXPS                              | View-only                     | No editing support                    |

> ⚠️ **Tip:** Non-OOXML formats may display layout differences or data loss when edited.

## 🤖 MCP server for AI agents

The app exposes an [MCP](https://modelcontextprotocol.io) server at `https://box.onlyoffice.com/mcp`, so an AI agent (for example the ONLYOFFICE Desktop AI agent) can work with your Box files:

- **All Box MCP tools** (search, list, read, organize, Box AI, ...) are proxied from [Box's MCP server](https://developer.box.com/guides/box-mcp/remote/) with the Box access you granted to ONLYOFFICE.
- **`open_in_onlyoffice`** opens a Box file in the ONLYOFFICE editor, so it is edited in place and every change is saved back to Box. It returns an `oo-office:` link for ONLYOFFICE Desktop and a browser link.

To connect ONLYOFFICE Desktop:

1. Open `https://box.onlyoffice.com/mcp/key` and sign in to Box if asked. The page shows a ready-made configuration with a personal MCP key and a **Copy configuration** button (clients sending `Accept: application/json` get the configuration itself):

   ```json
   {
     "mcpServers": {
       "onlyoffice-box": {
         "url": "https://box.onlyoffice.com/mcp",
         "headers": { "Authorization": "Bearer <key>" }
       }
     }
   }
   ```

2. In ONLYOFFICE Desktop, open **AI agent > MCP Servers > Edit configuration**, add the `onlyoffice-box` entry to `mcpServers` and save.
3. Sign in to Box in ONLYOFFICE Desktop (**Connect to cloud > Box**), so files opened by `open_in_onlyoffice` load in the editor.

The page always shows the same key for your account; a fresh key appears there every 30 days, and each key stays valid for up to 90 days (see the `X-MCP-Key-Expires` response header). Treat it like a password. **Revoke key** on the same page (`POST /mcp/key/revoke`) invalidates every key issued so far and shows a new one.

The gateway signs MCP keys with its own secret, `mcp.key_secret` in its configuration (or `MCP_KEY_SECRET`), a random value of at least 32 characters, e.g. `openssl rand -base64 48`; it does not start without one. To rotate it, set the new value and move the old one to `mcp.previous_key_secret` (`MCP_PREVIOUS_KEY_SECRET`) until users have copied the new configuration from `/mcp/key`.

A reverse proxy in front of the gateway must allow `/mcp` requests to take longer than 90 seconds (for example nginx `proxy_read_timeout 150;`): proxied Box tools such as Box AI can run that long, and the gateway answers a slow Box itself after 85 seconds.

Box's MCP server must be enabled for the enterprise by a Box admin (**Admin Console > Integrations > Box MCP server**). If it rejects the Box access you granted to ONLYOFFICE, the agent only gets `open_in_onlyoffice`.

## Project information

**Official project page:** [onlyoffice.com](https://www.onlyoffice.com/office-for-box)

**Source code:** [Repository](https://github.com/ONLYOFFICE/onlyoffice-box)

**Box App Center:** [ONLYOFFICE Docs](https://app.box.com/integrations/onlyoffice_personal/i)

## 💬 User Feedback & Support

We welcome community participation, technical insights, and feedback. For questions, issues, or troubleshooting, visit:

- **Report issues:** [GitHub Issues](https://github.com/ONLYOFFICE/onlyoffice-box/issues)
- **Community forum:** [ONLYOFFICE Community](https://community.onlyoffice.com/)
- **Feedback platform:** [Share ideas](https://feedback.onlyoffice.com/forums/966080-your-voice-matters)
- **Help for developers:** [API documentation](https://api.onlyoffice.com)

---