/**
 * MCP Shield — Dashboard Webview
 * ==============================
 *
 * Security notes for this file, because it is the one place where attacker-
 * controlled data meets a script-enabled context:
 *
 *   1. CONTENT SECURITY POLICY. The webview runs with `enableScripts: true`, so
 *      it needs a CSP. `script-src` is restricted to a per-render nonce, which
 *      means no inline event-handler attributes are permitted — every handler is
 *      attached from the nonced script via event delegation. `default-src 'none'`
 *      denies network access outright, so a redirected or injected resource
 *      cannot phone home.
 *
 *   2. ESCAPING. Server ids, tool names, descriptions and warning details all
 *      originate from the MCP server being inspected — which is precisely the
 *      component we assume may be hostile. Every one of those values is passed
 *      through `esc()` before it reaches `innerHTML`. Without that, a server
 *      advertising a tool named `<img src=x onerror=...>` would get script
 *      execution inside the dashboard of the tool auditing it.
 *
 *   3. NO REMOTE FONTS. The original loaded webfonts from Google Fonts. That
 *      leaked usage metadata to a third party, broke offline use, and would be
 *      denied by this CSP anyway. The stacks below fall back to system fonts.
 *
 * @param nonce      Fresh random value per render; must match the CSP header.
 * @param cspSource  `webview.cspSource` from the VS Code API.
 */
export function getWebviewContent(nonce: string, cspSource: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src ${cspSource} data:; style-src ${cspSource} 'unsafe-inline'; font-src ${cspSource}; script-src 'nonce-${nonce}';">
  <title>MCP Shield Dashboard</title>

  <style>
    :root {
      --bg-dark: #0A0D14;
      --bg-card: rgba(16, 22, 35, 0.7);
      --bg-card-hover: rgba(26, 34, 52, 0.85);
      --border-color: rgba(255, 255, 255, 0.08);
      --border-focus: rgba(0, 255, 102, 0.4);
      --text-main: #E2E8F0;
      --text-muted: #94A3B8;
      
      --color-primary: #00FF66; /* Secure emerald */
      --color-primary-glow: rgba(0, 255, 102, 0.15);
      --color-accent: #00F0FF; /* Electric cyan */
      --color-accent-glow: rgba(0, 240, 255, 0.15);
      --color-danger: #FF3B30; /* Neon red */
      --color-danger-glow: rgba(255, 59, 48, 0.15);
      --color-warning: #FFCC00; /* Gold warning */
      --color-warning-glow: rgba(255, 204, 0, 0.15);
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Plus Jakarta Sans', sans-serif;
      background-color: var(--bg-dark);
      color: var(--text-main);
      height: 100vh;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }

    /* Scrollbars */
    ::-webkit-scrollbar {
      width: 6px;
      height: 6px;
    }
    ::-webkit-scrollbar-track {
      background: transparent;
    }
    ::-webkit-scrollbar-thumb {
      background: rgba(255, 255, 255, 0.1);
      border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: rgba(255, 255, 255, 0.2);
    }

    /* Layout */
    .app-container {
      display: flex;
      flex: 1;
      height: 100%;
      overflow: hidden;
    }

    /* Sidebar */
    .sidebar {
      width: 260px;
      background: rgba(8, 11, 19, 0.95);
      border-right: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      padding: 24px 16px;
      gap: 32px;
      z-index: 10;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      padding-left: 8px;
    }

    .brand-icon {
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, var(--color-primary), var(--color-accent));
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      color: #000;
      font-size: 18px;
      box-shadow: 0 0 15px rgba(0, 255, 102, 0.4);
    }

    .brand-title {
      font-family: 'Outfit', sans-serif;
      font-weight: 700;
      font-size: 18px;
      letter-spacing: 0.5px;
      background: linear-gradient(120deg, #FFF, var(--text-muted));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .menu-list {
      display: flex;
      flex-direction: column;
      gap: 6px;
      list-style: none;
    }

    .menu-item {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      border-radius: 8px;
      color: var(--text-muted);
      font-weight: 500;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.2s ease;
      border: 1px solid transparent;
    }

    .menu-item:hover {
      color: #FFF;
      background: rgba(255, 255, 255, 0.03);
    }

    .menu-item.active {
      color: var(--color-primary);
      background: var(--color-primary-glow);
      border-color: rgba(0, 255, 102, 0.2);
      box-shadow: 0 4px 20px rgba(0, 255, 102, 0.05);
    }

    .status-header {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
    }

    .status-indicator {
      width: 8px;
      height: 8px;
      background-color: var(--color-primary);
      border-radius: 50%;
      box-shadow: 0 0 10px var(--color-primary);
    }

    .status-value {
      font-size: 15px;
      font-weight: 700;
      color: #FFF;
    }

    /* Main Content Area */
    .main-content {
      flex: 1;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      background: radial-gradient(circle at 50% 0%, rgba(0, 240, 255, 0.03), transparent 60%);
    }

    .header-bar {
      height: 72px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 32px;
    }

    .page-title {
      font-family: 'Outfit', sans-serif;
      font-size: 20px;
      font-weight: 600;
    }

    .view-pane {
      flex: 1;
      overflow-y: auto;
      padding: 32px;
      display: none;
    }

    .view-pane.active {
      display: block;
    }

    /* Dashboard Tab styling */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 20px;
      margin-bottom: 32px;
    }

    @media (max-width: 900px) {
      .metrics-grid {
        grid-template-columns: repeat(2, 1fr);
      }
      .dashboard-sections {
        grid-template-columns: 1fr !important;
      }
    }

    .metric-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 10px;
      position: relative;
      overflow: hidden;
      backdrop-filter: blur(10px);
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .metric-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 3px;
      background: transparent;
    }

    .metric-card.primary::before { background: var(--color-primary); }
    .metric-card.danger::before { background: var(--color-danger); }
    .metric-card.warning::before { background: var(--color-warning); }
    .metric-card.accent::before { background: var(--color-accent); }

    .metric-card:hover {
      transform: translateY(-4px);
      border-color: rgba(255, 255, 255, 0.15);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
    }

    .metric-label {
      font-size: 13px;
      color: var(--text-muted);
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .metric-value {
      font-family: 'Outfit', sans-serif;
      font-size: 32px;
      font-weight: 700;
      color: #FFF;
      line-height: 1;
    }

    .dashboard-sections {
      display: grid;
      grid-template-columns: 3fr 2fr;
      gap: 24px;
    }

    .section-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 24px;
      backdrop-filter: blur(10px);
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 16px;
    }

    .section-title {
      font-family: 'Outfit', sans-serif;
      font-size: 16px;
      font-weight: 600;
    }

    .view-all-btn {
      font-size: 12px;
      color: var(--color-accent);
      cursor: pointer;
      text-decoration: none;
      font-weight: 500;
    }

    .view-all-btn:hover {
      text-decoration: underline;
    }

    /* Tables */
    .table-container {
      overflow-x: auto;
      width: 100%;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }

    th {
      font-size: 12px;
      font-weight: 600;
      color: var(--text-muted);
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-color);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    td {
      padding: 14px 16px;
      font-size: 13px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
    }

    tr:last-child td {
      border-bottom: none;
    }

    tr.clickable {
      cursor: pointer;
      transition: background 0.2s ease;
    }

    tr.clickable:hover {
      background: rgba(255, 255, 255, 0.02);
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.2px;
    }

    .badge-success {
      background: var(--color-primary-glow);
      color: var(--color-primary);
      border: 1px solid rgba(0, 255, 102, 0.2);
    }

    .badge-danger {
      background: var(--color-danger-glow);
      color: var(--color-danger);
      border: 1px solid rgba(255, 59, 48, 0.2);
    }

    .badge-warning {
      background: var(--color-warning-glow);
      color: var(--color-warning);
      border: 1px solid rgba(255, 204, 0, 0.2);
    }

    /* Filter Toolbar */
    .filter-toolbar {
      display: flex;
      gap: 16px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }

    .search-input {
      flex: 1;
      min-width: 200px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 10px 16px;
      color: #FFF;
      font-family: inherit;
      font-size: 13px;
      outline: none;
      transition: all 0.2s ease;
    }

    .search-input:focus {
      border-color: var(--color-primary);
      box-shadow: 0 0 10px rgba(0, 255, 102, 0.1);
    }

    .select-input {
      background: rgba(8, 11, 19, 0.9);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 10px 16px;
      color: #FFF;
      font-family: inherit;
      font-size: 13px;
      outline: none;
      cursor: pointer;
    }

    .select-input:focus {
      border-color: var(--color-primary);
    }

    /* Config Assistant styles */
    .config-accordion {
      display: flex;
      flex-direction: column;
      gap: 16px;
    }

    .config-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      overflow: hidden;
    }

    .config-card-header {
      padding: 18px 24px;
      background: rgba(255, 255, 255, 0.01);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .config-title-group {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .config-name {
      font-family: 'Outfit', sans-serif;
      font-size: 16px;
      font-weight: 600;
    }

    .config-path {
      font-size: 11px;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
    }

    .config-card-body {
      padding: 24px;
    }

    .server-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .server-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 8px;
    }

    .server-info {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .server-id {
      font-weight: 600;
      font-size: 14px;
      color: #FFF;
    }

    .server-cmd {
      font-size: 11px;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
    }

    /* Buttons & Switch UI */
    .btn {
      padding: 8px 16px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 12px;
      cursor: pointer;
      transition: all 0.2s ease;
      border: 1px solid transparent;
      outline: none;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }

    .btn-primary {
      background: var(--color-primary);
      color: #000;
    }

    .btn-primary:hover {
      background: #00E55C;
      box-shadow: 0 0 12px rgba(0, 255, 102, 0.3);
    }

    .btn-outline {
      border-color: var(--border-color);
      background: transparent;
      color: var(--text-main);
    }

    .btn-outline:hover {
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(255, 255, 255, 0.2);
    }

    /* Policies Tab styling */
    .policy-manager {
      display: grid;
      grid-template-columns: 1fr 2fr;
      gap: 32px;
      height: 100%;
    }

    .server-sidebar {
      background: rgba(255, 255, 255, 0.01);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .server-list-item {
      padding: 12px 16px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      color: var(--text-muted);
      transition: all 0.2s ease;
      border: 1px solid transparent;
    }

    .server-list-item:hover {
      background: rgba(255, 255, 255, 0.02);
      color: #FFF;
    }

    .server-list-item.selected {
      background: var(--color-accent-glow);
      color: var(--color-accent);
      border-color: rgba(0, 240, 255, 0.2);
    }

    .policy-editor-panel {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 32px;
      display: none;
      flex-direction: column;
      gap: 24px;
    }

    .policy-editor-panel.visible {
      display: flex;
    }

    .cell-truncate {
      max-width: 300px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      cursor: help;
    }

    .form-group {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .form-label {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-main);
      display: flex;
      justify-content: space-between;
    }

    .form-label-desc {
      font-size: 11px;
      color: var(--text-muted);
      font-weight: 400;
    }

    .textarea-input {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 12px 16px;
      color: #FFF;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      outline: none;
      resize: vertical;
      min-height: 80px;
    }

    .textarea-input:focus {
      border-color: var(--color-primary);
    }

    .toggle-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 8px;
    }

    .toggle-info {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .toggle-title {
      font-size: 14px;
      font-weight: 600;
    }

    .toggle-desc {
      font-size: 11px;
      color: var(--text-muted);
    }

    /* Switch input */
    .switch {
      position: relative;
      display: inline-block;
      width: 44px;
      height: 24px;
    }

    .switch input {
      opacity: 0;
      width: 0;
      height: 0;
    }

    .slider {
      position: absolute;
      cursor: pointer;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-color: rgba(255, 255, 255, 0.1);
      transition: .4s;
      border-radius: 24px;
      border: 1px solid var(--border-color);
    }

    .slider:before {
      position: absolute;
      content: "";
      height: 16px;
      width: 16px;
      left: 3px;
      bottom: 3px;
      background-color: #FFF;
      transition: .4s;
      border-radius: 50%;
    }

    input:checked + .slider {
      background-color: var(--color-primary);
    }

    input:checked + .slider:before {
      transform: translateX(20px);
      background-color: #000;
    }

    /* Modal / Drawer inspect panel */
    .drawer-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.55);
      z-index: 99;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s ease;
    }

    .drawer-backdrop.open {
      opacity: 1;
      pointer-events: all;
    }

    .drawer {
      position: fixed;
      top: 0;
      right: -550px;
      width: 550px;
      height: 100vh;
      background: rgba(10, 13, 20, 0.98);
      border-left: 1px solid var(--border-color);
      box-shadow: -10px 0 40px rgba(0, 0, 0, 0.6);
      transition: right 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      z-index: 100;
      display: flex;
      flex-direction: column;
    }

    .drawer.open {
      right: 0;
    }

    .drawer-header {
      padding: 24px;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .drawer-title {
      font-family: 'Outfit', sans-serif;
      font-size: 18px;
      font-weight: 600;
    }

    .close-btn {
      font-size: 20px;
      color: var(--text-muted);
      cursor: pointer;
      background: transparent;
      border: none;
      outline: none;
    }

    .close-btn:hover {
      color: #FFF;
    }

    .drawer-body {
      padding: 24px;
      flex: 1;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    .info-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
    }

    .info-label {
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      font-weight: 600;
      margin-bottom: 6px;
    }

    .info-value {
      font-size: 14px;
      color: #FFF;
      font-weight: 500;
    }

    .code-block {
      background: #06090F;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 16px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: #89DDFF;
      overflow-x: auto;
      white-space: pre-wrap;
    }

    @keyframes pulse {
      0% {
        transform: scale(0.95);
        box-shadow: 0 0 0 0 rgba(0, 255, 102, 0.7);
      }
      70% {
        transform: scale(1);
        box-shadow: 0 0 0 6px rgba(0, 255, 102, 0);
      }
      100% {
        transform: scale(0.95);
        box-shadow: 0 0 0 0 rgba(0, 255, 102, 0);
      }
    }

    @keyframes shimmer {
      0% { background-position: -200% center; }
      100% { background-position: 200% center; }
    }

    .status-indicator {
      animation: pulse 2s infinite;
      flex-shrink: 0;
    }

    .status-card {
      margin-top: auto;
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
      position: relative;
      overflow: hidden;
    }

    .status-card::after {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(105deg, transparent 40%, rgba(255,255,255,0.03) 50%, transparent 60%);
      background-size: 200% 100%;
      animation: shimmer 3s linear infinite;
      pointer-events: none;
    }
  </style>
</head>
<body>

  <div class="app-container">
    <!-- Sidebar -->
    <div class="sidebar">
      <div class="brand">
        <div class="brand-icon">S</div>
        <div class="brand-title">MCP Shield</div>
      </div>
      
      <ul class="menu-list">
        <li class="menu-item active" data-action="tab" data-tab="dashboard">
          <svg style="width: 18px; height: 18px;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2H6a2 2 0 01-2-2v-4zM14 16a2 2 0 012-2h2a2 2 0 012 2v4a2 2 0 01-2 2h-2a2 2 0 01-2-2v-4z"></path></svg>
          Dashboard
        </li>
        <li class="menu-item" data-action="tab" data-tab="audit">
          <svg style="width: 18px; height: 18px;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
          Audit Logs
        </li>
        <li class="menu-item" data-action="tab" data-tab="warnings">
          <svg style="width: 18px; height: 18px;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
          Security Warnings
        </li>
        <li class="menu-item" data-action="tab" data-tab="policies">
          <svg style="width: 18px; height: 18px;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
          Policies
        </li>
        <li class="menu-item" data-action="tab" data-tab="configs">
          <svg style="width: 18px; height: 18px;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
          Configs
        </li>
      </ul>
      
      <div class="status-card">
        <div class="status-header">
          <div class="status-indicator"></div>
          <span>MONITOR SYSTEM</span>
        </div>
        <div class="status-value">GATEWAY PROTECTED</div>
      </div>
    </div>

    <!-- Main Content Area -->
    <div class="main-content">
      <div class="header-bar">
        <div class="page-title" id="pane-title">Dashboard Overview</div>
      </div>

      <!-- Tab: Dashboard -->
      <div id="pane-dashboard" class="view-pane active">
        <div class="metrics-grid">
          <div class="metric-card primary">
            <span class="metric-label">Shielded Servers</span>
            <span class="metric-value" id="stat-servers">0</span>
          </div>
          <div class="metric-card accent">
            <span class="metric-label">Total Tool Calls</span>
            <span class="metric-value" id="stat-calls">0</span>
          </div>
          <div class="metric-card danger">
            <span class="metric-label">Prevented Attacks</span>
            <span class="metric-value" id="stat-blocked">0</span>
          </div>
          <div class="metric-card warning">
            <span class="metric-label">Security Smells</span>
            <span class="metric-value" id="stat-warnings">0</span>
          </div>
        </div>

        <div class="dashboard-sections">
          <div class="section-card">
            <div class="section-header">
              <span class="section-title">Recent Activity Logs</span>
              <span class="view-all-btn" data-action="tab" data-tab="audit">View all</span>
            </div>
            <div class="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Server</th>
                    <th>Tool</th>
                    <th>Decision</th>
                  </tr>
                </thead>
                <tbody id="recent-logs-tbody">
                  <tr>
                    <td colspan="4" style="text-align: center; color: var(--text-muted);">No activity recorded yet.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div class="section-card">
            <div class="section-header">
              <span class="section-title">Latest Security Smells</span>
              <span class="view-all-btn" data-action="tab" data-tab="warnings">View all</span>
            </div>
            <div class="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Server</th>
                    <th>Tool</th>
                    <th>Smell Details</th>
                  </tr>
                </thead>
                <tbody id="recent-warnings-tbody">
                  <tr>
                    <td colspan="3" style="text-align: center; color: var(--text-muted);">No warnings detected.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab: Audit Logs -->
      <div id="pane-audit" class="view-pane">
        <div class="filter-toolbar">
          <input type="text" class="search-input" id="log-search" placeholder="Search by tool, args, or reasons..." data-action="filter">
          <select class="select-input" id="log-server-filter" data-action="filter">
            <option value="">All Servers</option>
          </select>
          <select class="select-input" id="log-status-filter" data-action="filter">
            <option value="">All Decisions</option>
            <option value="ALLOWED">Allowed</option>
            <option value="BLOCKED">Blocked</option>
          </select>
        </div>

        <div class="section-card" style="padding: 0; overflow: hidden;">
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Server</th>
                  <th>Tool</th>
                  <th>Decision</th>
                  <th>Explanation / Context</th>
                </tr>
              </thead>
              <tbody id="audit-logs-tbody">
                <tr>
                  <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">No logs recorded yet.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab: Security Warnings -->
      <div id="pane-warnings" class="view-pane">
        <div class="section-card" style="padding: 0; overflow: hidden;">
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Server</th>
                  <th>Tool Name</th>
                  <th>Smell Type</th>
                  <th>Details</th>
                  <th>Sanitization</th>
                </tr>
              </thead>
              <tbody id="warnings-tbody">
                <tr>
                  <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No warnings recorded.</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Tab: Policies -->
      <div id="pane-policies" class="view-pane">
        <div class="policy-manager">
          <div class="server-sidebar" id="policy-server-list">
            <!-- Populated dynamically -->
          </div>

          <div class="policy-editor-panel" id="policy-editor">
            <h3 class="section-title" id="policy-editor-title" style="font-size: 18px;">Edit Server Policy</h3>
            
            <div class="form-group">
              <label class="form-label">Security Mode</label>
              <select class="select-input" id="policy-mode" style="width: 100%;">
                <option value="Permissive">Permissive (Log Everything, Enforce Nothing)</option>
                <option value="Gated">Gated (Prompt Developer for All Tools)</option>
                <option value="Strict">Strict (Automated Security Rules + Enforce)</option>
              </select>
            </div>

            <div class="toggle-row">
              <div class="toggle-info">
                <span class="toggle-title">Read-Only Mode</span>
                <span class="toggle-desc">Blocks all actions that alter filesystem or execute processes.</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="policy-readonly">
                <span class="slider"></span>
              </label>
            </div>

            <div class="form-group">
              <label class="form-label">
                <span>Authorized Paths</span>
                <span class="form-label-desc">One path per line. Traversal outside these paths is blocked.</span>
              </label>
              <textarea class="textarea-input" id="policy-paths" placeholder="e.g. C:\\Projects\\MyWorkspace"></textarea>
            </div>

            <div class="form-group">
              <label class="form-label">
                <span>Authorized Domains</span>
                <span class="form-label-desc">One domain per line. e.g. api.github.com, *.npm.org</span>
              </label>
              <textarea class="textarea-input" id="policy-domains" placeholder="e.g. github.com"></textarea>
            </div>

            <div class="form-group">
              <label class="form-label">
                <span>Disabled Tools</span>
                <span class="form-label-desc">One tool name per line. Blocked immediately.</span>
              </label>
              <textarea class="textarea-input" id="policy-disabled-tools" placeholder="e.g. delete_file"></textarea>
            </div>

            <div class="form-group">
              <label class="form-label">
                <span>Max Payload Size (KB)</span>
                <span class="form-label-desc">Limit tool response sizes to protect the AI context window. Set to 0 to disable. e.g. 500 = 500 KB.</span>
              </label>
              <input type="number" class="search-input" id="policy-max-payload" min="0" step="1" placeholder="0 (Disabled)" style="width: 100%;">
            </div>

            <div style="display: flex; gap: 12px; margin-top: 12px;">
              <button class="btn btn-primary" data-action="save-policy">Save Policy</button>
            </div>
          </div>

          <div class="policy-editor-panel visible" id="policy-editor-placeholder" style="justify-content: center; align-items: center; text-align: center; color: var(--text-muted);">
            <svg style="width: 48px; height: 48px; margin-bottom: 16px; opacity: 0.5;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
            Select an MCP Server from the left list to edit its security policy.
          </div>
        </div>
      </div>

      <!-- Tab: Config Assistant -->
      <div id="pane-configs" class="view-pane">
        <div class="filter-toolbar" style="justify-content: flex-end;">
          <button class="btn btn-outline" data-action="rescan">
            <svg style="width: 14px; height: 14px;" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H17m0 0V4m0 4h4"></path></svg>
            Rescan Configs
          </button>
        </div>

        <div class="config-accordion" id="config-accordion-list">
          <!-- Populated dynamically -->
        </div>
      </div>
    </div>
  </div>

  <!-- Drawer Backdrop -->
  <div class="drawer-backdrop" id="drawer-backdrop" data-action="close-drawer"></div>

  <!-- Detail Drawer -->
  <div class="drawer" id="inspect-drawer">
    <div class="drawer-header">
      <span class="drawer-title" id="drawer-title">Inspect Tool Call</span>
      <button class="close-btn" data-action="close-drawer">&times;</button>
    </div>
    <div class="drawer-body">
      <div class="info-card">
        <div class="info-label">Server ID</div>
        <div class="info-value" id="drawer-server">filesystem</div>
      </div>
      <div class="info-card">
        <div class="info-label">Tool Name</div>
        <div class="info-value" id="drawer-tool" style="font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--color-accent);">write_file</div>
      </div>
      <div class="info-card">
        <div class="info-label">Timestamp</div>
        <div class="info-value" id="drawer-time">2026-06-07 12:00:00</div>
      </div>
      <div class="info-card">
        <div class="info-label">Decision Status</div>
        <div id="drawer-decision-badge">ALLOWED</div>
      </div>
      <div class="info-card">
        <div class="info-label">Reason / Justification</div>
        <div class="info-value" id="drawer-reason" style="font-size: 13px;">Passed all automated security rules.</div>
      </div>
      <div class="info-card" style="display: flex; flex-direction: column; gap: 8px;">
        <div class="info-label">Tool Arguments</div>
        <div class="code-block" id="drawer-args">{}</div>
      </div>
    </div>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();

    /**
     * Escape a value for safe insertion into HTML.
     *
     * Everything rendered below originates from an MCP server we explicitly do
     * not trust, so this is applied to every interpolated value — not just the
     * ones that look risky. Ampersand must be replaced first or it would
     * double-escape the entities introduced afterwards.
     */
    function esc(value) {
      return String(value === null || value === undefined ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    /** Risk score (0-100) to a CSS colour variable. */
    function riskColor(score) {
      if (score >= 100) return 'var(--color-danger)';
      if (score >= 75) return 'var(--color-danger)';
      if (score >= 45) return 'var(--color-warning)';
      if (score > 0) return 'var(--color-accent)';
      return 'var(--text-muted)';
    }

    // Global memory store
    let globalLogs = [];
    let globalWarnings = [];
    let globalPolicies = [];
    let globalConfigs = [];
    let globalRules = [];

    let activeServerIdForPolicy = null;

    // Handle messages from VS Code extension
    window.addEventListener('message', event => {
      const message = event.data;
      if (message.type === 'updateData') {
        globalLogs = message.logs || [];
        globalWarnings = message.warnings || [];
        globalPolicies = message.policies || [];
        globalConfigs = message.configs || [];
        globalRules = message.rules || [];

        renderDashboard();
        renderAuditLogs();
        renderWarnings();
        renderPolicies();
        renderConfigs();
      }
    });

    /**
     * Single delegated click handler.
     *
     * The CSP restricts script-src to a nonce, which disallows inline `onclick`
     * attributes. Rather than attach a listener per element, elements declare
     * their intent with `data-action` and this resolves it. Handles dynamically
     * created rows too, since the listener is on the document.
     */
    document.addEventListener('click', (event) => {
      const target = event.target instanceof Element
        ? event.target.closest('[data-action]')
        : null;
      if (!target) return;

      switch (target.getAttribute('data-action')) {
        case 'tab':
          switchTab(target.getAttribute('data-tab'));
          break;
        case 'save-policy':
          saveActivePolicy();
          break;
        case 'rescan':
          triggerScan();
          break;
        case 'close-drawer':
          closeDrawer();
          break;
        case 'toggle-shield':
          // Values arrive as attributes rather than interpolated into a JS
          // string, so a server id containing a quote cannot break out and
          // execute. The original built an onclick attribute by concatenation.
          toggleShield(
            target.getAttribute('data-config-path'),
            target.getAttribute('data-server-id'),
            target.getAttribute('data-shield') === 'true'
          );
          break;
        case 'revoke-rule':
          revokeRule(
            target.getAttribute('data-server-id'),
            target.getAttribute('data-tool-name')
          );
          break;
      }
    });

    // Search and filter inputs.
    document.addEventListener('input', (event) => {
      const el = event.target;
      if (el instanceof Element && el.getAttribute('data-action') === 'filter') {
        filterLogs();
      }
    });
    document.addEventListener('change', (event) => {
      const el = event.target;
      if (el instanceof Element && el.getAttribute('data-action') === 'filter') {
        filterLogs();
      }
    });

    // Tab Switching Logic
    function switchTab(tabId) {
      document.querySelectorAll('.menu-item').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.view-pane').forEach(el => el.classList.remove('active'));
      
      const paneTitle = document.getElementById('pane-title');
      const pane = document.getElementById('pane-' + tabId);
      
      if (pane) {
        pane.classList.add('active');
        
        // Highlight the matching menu item. Reads data-tab rather than parsing
        // the old onclick attribute, which no longer exists under the CSP.
        const menuItems = document.querySelectorAll('.menu-item');
        for (const item of menuItems) {
          if (item.getAttribute('data-tab') === tabId) {
            item.classList.add('active');
            break;
          }
        }
        
        // Update Title
        switch(tabId) {
          case 'dashboard': paneTitle.innerText = "Dashboard Overview"; break;
          case 'audit': paneTitle.innerText = "Audit Logs"; break;
          case 'warnings': paneTitle.innerText = "Security Warnings"; break;
          case 'policies': paneTitle.innerText = "Security Policies"; break;
          case 'configs': paneTitle.innerText = "Shield Assistant"; break;
        }
      }
      closeDrawer();
    }

    // Dashboard Tab Render
    function renderDashboard() {
      // Metrics
      const totalCalls = globalLogs.length;
      const blockedCalls = globalLogs.filter(l => l.decision === 'BLOCKED').length;
      const totalWarnings = globalWarnings.length;
      
      // Calculate active servers
      const activeServers = new Set();
      globalConfigs.forEach(c => c.servers.forEach(s => {
        if (s.isShielded) activeServers.add(s.id);
      }));
      
      document.getElementById('stat-servers').innerText = activeServers.size;
      document.getElementById('stat-calls').innerText = totalCalls;
      document.getElementById('stat-blocked').innerText = blockedCalls;
      document.getElementById('stat-warnings').innerText = totalWarnings;

      // Update monitor system card status
      const indicator = document.querySelector('.status-indicator');
      const valueSpan = document.querySelector('.status-value');
      
      if (blockedCalls > 0 || totalWarnings > 0) {
        indicator.style.backgroundColor = 'var(--color-warning)';
        indicator.style.boxShadow = '0 0 10px var(--color-warning)';
        valueSpan.innerText = 'RISKS DETECTED';
      } else {
        indicator.style.backgroundColor = 'var(--color-primary)';
        indicator.style.boxShadow = '0 0 10px var(--color-primary)';
        valueSpan.innerText = 'GATEWAY PROTECTED';
      }

      // Recent logs (top 5)
      const tbodyLogs = document.getElementById('recent-logs-tbody');
      tbodyLogs.innerHTML = '';
      if (globalLogs.length === 0) {
        tbodyLogs.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No activity recorded yet.</td></tr>';
      } else {
        globalLogs.slice(0, 5).forEach(log => {
          const tr = document.createElement('tr');
          tr.className = 'clickable';
          tr.onclick = () => openInspectDrawer(log);
          
          const badgeClass = log.decision === 'ALLOWED' ? 'badge-success' : 'badge-danger';

          tr.innerHTML =
            '<td style="color: var(--text-muted);">' + esc(formatTime(log.timestamp)) + '</td>' +
            '<td style="font-weight: 500;">' + esc(log.server_id) + '</td>' +
            '<td style="font-family: \'JetBrains Mono\', monospace; font-size: 12px; color: var(--color-accent);">' + esc(log.tool_name) + '</td>' +
            '<td><span class="badge ' + badgeClass + '">' + esc(log.decision) + '</span></td>';

          tbodyLogs.appendChild(tr);
        });
      }

      // Recent warnings (top 5)
      const tbodyWarnings = document.getElementById('recent-warnings-tbody');
      tbodyWarnings.innerHTML = '';
      if (globalWarnings.length === 0) {
        tbodyWarnings.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No warnings detected.</td></tr>';
      } else {
        globalWarnings.slice(0, 5).forEach(warn => {
          const tr = document.createElement('tr');
          tr.innerHTML =
            '<td style="font-weight: 500;">' + esc(warn.server_id) + '</td>' +
            '<td style="font-family: \'JetBrains Mono\', monospace; font-size: 12px; color: var(--color-accent);">' + esc(warn.tool_name) + '</td>' +
            '<td style="color: var(--color-danger); font-size: 12px;">' + esc(warn.details) + '</td>';
          tbodyWarnings.appendChild(tr);
        });
      }
    }

    // Audit Logs Tab Render
    function renderAuditLogs() {
      // Re-populate filter dropdown for servers
      const serverFilter = document.getElementById('log-server-filter');
      const selectedServer = serverFilter.value;
      serverFilter.innerHTML = '<option value="">All Servers</option>';
      
      const serverNames = new Set(globalLogs.map(l => l.server_id));
      serverNames.forEach(name => {
        const opt = document.createElement('option');
        opt.value = name;
        opt.innerText = name;
        if (name === selectedServer) opt.selected = true;
        serverFilter.appendChild(opt);
      });

      filterLogs();
    }

    function filterLogs() {
      const search = document.getElementById('log-search').value.toLowerCase();
      const server = document.getElementById('log-server-filter').value;
      const status = document.getElementById('log-status-filter').value;

      const tbody = document.getElementById('audit-logs-tbody');
      tbody.innerHTML = '';

      const filtered = globalLogs.filter(log => {
        const matchesSearch = log.tool_name.toLowerCase().includes(search) || 
                              log.arguments.toLowerCase().includes(search) || 
                              log.reason.toLowerCase().includes(search);
        const matchesServer = !server || log.server_id === server;
        const matchesStatus = !status || log.decision === status;
        
        return matchesSearch && matchesServer && matchesStatus;
      });

      if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No matching logs found.</td></tr>';
      } else {
        filtered.forEach(log => {
          const tr = document.createElement('tr');
          tr.className = 'clickable';
          tr.onclick = () => openInspectDrawer(log);

          const badgeClass = log.decision === 'ALLOWED' ? 'badge-success' : 'badge-danger';
          const score = Number(log.risk_score) || 0;

          tr.innerHTML =
            '<td style="color: var(--text-muted);">' + esc(formatTime(log.timestamp)) + '</td>' +
            '<td style="font-weight: 500;">' + esc(log.server_id) + '</td>' +
            '<td style="font-family: \'JetBrains Mono\', monospace; font-size: 12px; color: var(--color-accent);">' + esc(log.tool_name) + '</td>' +
            '<td><span class="badge ' + badgeClass + '">' + esc(log.decision) + '</span></td>' +
            '<td style="font-weight: 600; color: ' + riskColor(score) + ';">' + (score > 0 ? esc(score) : '—') + '</td>' +
            '<td><span class="cell-truncate" title="' + esc(log.reason) + '">' + esc(log.reason) + '</span></td>';

          tbody.appendChild(tr);
        });
      }
    }

    // Security Warnings Tab Render
    function renderWarnings() {
      const tbody = document.getElementById('warnings-tbody');
      tbody.innerHTML = '';

      if (globalWarnings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">No warnings recorded.</td></tr>';
      } else {
        globalWarnings.forEach(warn => {
          const tr = document.createElement('tr');
          
          tr.innerHTML = 
            '<td style="color: var(--text-muted);">' + formatTime(warn.timestamp) + '</td>' +
            '<td style="font-weight: 500;">' + warn.server_id + '</td>' +
            '<td style="font-family: \'JetBrains Mono\', monospace; font-size: 12px; color: var(--color-accent);">' + warn.tool_name + '</td>' +
            '<td><span class="badge badge-warning">' + warn.smell_type + '</span></td>' +
            '<td style="font-size: 12px; color: var(--text-muted);">' + warn.details + '</td>' +
            '<td><span class="badge ' + (warn.sanitized ? 'badge-success">SANITIZED' : 'badge-warning">DETECTED') + '</span></td>';
          
          tbody.appendChild(tr);
        });
      }
    }

    // Policies Tab Render
    function renderPolicies() {
      // Populate Server Sidebar list
      const sidebar = document.getElementById('policy-server-list');
      sidebar.innerHTML = '';
      
      // Get unique servers from policies + configs
      const allServerIds = new Set();
      globalPolicies.forEach(p => allServerIds.add(p.server_id));
      globalConfigs.forEach(c => c.servers.forEach(s => allServerIds.add(s.id)));

      if (allServerIds.size === 0) {
        sidebar.innerHTML = '<div style="font-size:12px; color:var(--text-muted); text-align:center; padding: 20px;">No servers detected.</div>';
        return;
      }

      allServerIds.forEach(serverId => {
        const item = document.createElement('div');
        item.className = 'server-list-item' + (activeServerIdForPolicy === serverId ? ' selected' : '');
        item.innerText = serverId;
        item.onclick = () => selectServerForPolicy(serverId);
        sidebar.appendChild(item);
      });
    }

    function selectServerForPolicy(serverId) {
      activeServerIdForPolicy = serverId;
      renderPolicies();

      // Show editor
      document.getElementById('policy-editor-placeholder').classList.remove('visible');
      document.getElementById('policy-editor').classList.add('visible');
      
      document.getElementById('policy-editor-title').innerText = 'Edit Policy: ' + serverId;

      // Get policy details
      let policy = globalPolicies.find(p => p.server_id === serverId);
      if (!policy) {
        policy = {
          server_id: serverId,
          mode: 'Gated',
          readonly: 0,
          allowed_paths: '[]',
          allowed_domains: '[]',
          disabled_tools: '[]'
        };
      }

      // Populate form fields
      document.getElementById('policy-mode').value = policy.mode;
      document.getElementById('policy-readonly').checked = policy.readonly === 1;
      
      try {
        document.getElementById('policy-paths').value = JSON.parse(policy.allowed_paths).join('\\n');
      } catch {
        document.getElementById('policy-paths').value = '';
      }
      
      try {
        document.getElementById('policy-domains').value = JSON.parse(policy.allowed_domains).join('\\n');
      } catch {
        document.getElementById('policy-domains').value = '';
      }

      try {
        document.getElementById('policy-disabled-tools').value = JSON.parse(policy.disabled_tools).join('\\n');
      } catch {
        document.getElementById('policy-disabled-tools').value = '';
      }

      document.getElementById('policy-max-payload').value = policy.max_payload_kb || 0;
    }

    function saveActivePolicy() {
      if (!activeServerIdForPolicy) return;
      
      const mode = document.getElementById('policy-mode').value;
      const readonly = document.getElementById('policy-readonly').checked ? 1 : 0;
      
      const paths = document.getElementById('policy-paths').value.split('\\n').map(p => p.trim()).filter(p => p.length > 0);
      const domains = document.getElementById('policy-domains').value.split('\\n').map(d => d.trim()).filter(d => d.length > 0);
      const disabledTools = document.getElementById('policy-disabled-tools').value.split('\\n').map(t => t.trim()).filter(t => t.length > 0);
      const maxPayloadKb = parseInt(document.getElementById('policy-max-payload').value, 10) || 0;

      const policy = {
        server_id: activeServerIdForPolicy,
        mode,
        readonly,
        allowed_paths: JSON.stringify(paths),
        allowed_domains: JSON.stringify(domains),
        disabled_tools: JSON.stringify(disabledTools),
        status: 'Shielded',
        max_payload_kb: maxPayloadKb
      };

      vscode.postMessage({
        command: 'savePolicy',
        policy: policy
      });
    }

    // Config Assistant Tab Render
    function renderConfigs() {
      const listContainer = document.getElementById('config-accordion-list');
      listContainer.innerHTML = '';

      if (globalConfigs.length === 0) {
        listContainer.innerHTML = 
          '<div class="section-card" style="text-align: center; padding: 48px 32px; color: var(--text-muted);">' +
            '<svg style="width:48px;height:48px;margin:0 auto 16px;display:block;opacity:0.35;" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>' +
            '<div style="font-size:15px;font-weight:600;color:var(--text-main);margin-bottom:8px;">No MCP Configs Found</div>' +
            '<div style="font-size:13px;max-width:360px;margin:0 auto;line-height:1.6;">No MCP configuration files were detected in standard app storage directories. Click <strong style="color:var(--text-main);">Rescan Configs</strong> to search again.</div>' +
          '</div>';
        return;
      }

      globalConfigs.forEach(config => {
        const card = document.createElement('div');
        card.className = 'config-card';
        
        const cardHeader = document.createElement('div');
        cardHeader.className = 'config-card-header';
        cardHeader.innerHTML = 
          '<div class="config-title-group">' +
            '<span class="config-name">' + config.name + '</span>' +
            '<span class="config-path">' + config.path + '</span>' +
          '</div>';
        
        const cardBody = document.createElement('div');
        cardBody.className = 'config-card-body';
        
        const serverList = document.createElement('div');
        serverList.className = 'server-list';
        
        if (config.servers.length === 0) {
          serverList.innerHTML = '<div style="font-size:13px; color:var(--text-muted); text-align:center;">No MCP servers configured in this file.</div>';
        } else {
          config.servers.forEach(server => {
            const row = document.createElement('div');
            row.className = 'server-row';
            
            const btnText = server.isShielded ? 'Unshield' : 'Shield';
            const btnClass = server.isShielded ? 'btn-outline' : 'btn-primary';
            const shieldBadge = server.isShielded 
              ? '<span class="badge badge-success" style="margin-left: 10px;">Shielded</span>' 
              : '<span class="badge badge-danger" style="margin-left: 10px; opacity:0.6;">Unshielded</span>';
            
            row.innerHTML = 
              '<div class="server-info">' +
                '<div style="display:flex; align-items:center;">' +
                  '<span class="server-id">' + server.id + '</span>' +
                  shieldBadge +
                '</div>' +
                '<span class="server-cmd">' + server.command + ' ' + server.args.join(' ') + '</span>' +
              '</div>' +
              '<button class="btn ' + btnClass + '" onclick="toggleShield(\'' + config.path + '\', \'' + server.id + '\', ' + !server.isShielded + ')">' +
                btnText +
              '</button>';
            serverList.appendChild(row);
          });
        }
        
        cardBody.appendChild(serverList);
        card.appendChild(cardHeader);
        card.appendChild(cardBody);
        listContainer.appendChild(card);
      });
    }

    function toggleShield(configPath, serverId, shield) {
      vscode.postMessage({
        command: 'toggleShield',
        configPath,
        serverId,
        shield
      });
    }

    function triggerScan() {
      vscode.postMessage({
        command: 'scan'
      });
    }

    // Inspect Drawer Actions
    function openInspectDrawer(log) {
      document.getElementById('drawer-server').innerText = log.server_id;
      document.getElementById('drawer-tool').innerText = log.tool_name;
      document.getElementById('drawer-time').innerText = formatTimeFull(log.timestamp);
      
      const badge = document.getElementById('drawer-decision-badge');
      badge.className = 'badge ' + (log.decision === 'ALLOWED' ? 'badge-success' : 'badge-danger');
      badge.innerText = log.decision;
      
      document.getElementById('drawer-reason').innerText = log.reason;
      
      try {
        const prettyArgs = JSON.stringify(JSON.parse(log.arguments), null, 2);
        document.getElementById('drawer-args').innerText = prettyArgs;
      } catch {
        document.getElementById('drawer-args').innerText = log.arguments;
      }

      document.getElementById('inspect-drawer').classList.add('open');
      document.getElementById('drawer-backdrop').classList.add('open');
      document.body.style.overflow = 'hidden';
    }

    function closeDrawer() {
      document.getElementById('inspect-drawer').classList.remove('open');
      document.getElementById('drawer-backdrop').classList.remove('open');
      document.body.style.overflow = '';
    }

    // Helper functions
    function formatTime(timestamp) {
      const date = new Date(timestamp);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }

    function formatTimeFull(timestamp) {
      const date = new Date(timestamp);
      return date.toLocaleString();
    }
  </script>
</body>
</html>`;
}
