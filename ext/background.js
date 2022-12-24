function browserAPI() {
  return globalThis.browser || globalThis.chrome;
}

function storageAPI() {
  return browserAPI().storage.local;
}

browserAPI().runtime.onMessageExternal.addListener(
  async (request, sender, sendResponse) => {
    switch (request.op) {
      case "ping":
        storageAPI().get(["jwt", "endpoint"], (items) => {
          sendResponse({ op: "pong", connected: items.jwt && items.endpoint });
        });
        return;
      case "set_auth":
        const u = new URL(sender.url);
        await storageAPI().clear();
        await storageAPI().set({
          endpoint: `${u.protocol}//${u.host}/rpc/2022-12-22`,
          jwt: request.jwt,
        });
        sendResponse({ op: "set_auth_confirm" });
        break;
    }
  }
);
