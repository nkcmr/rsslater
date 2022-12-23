// build instructions: copy-paste this into: https://skalman.github.io/UglifyJS-online/
(function () {
  // ensure fetch isn't hijacked
  if (fetch.toString() !== "function fetch() { [native code] }") {
    alert(
      "RSSLater: fetch() is hijacked. refusing to complete operation due to security concerns."
    );
    return;
  }
  fetch("{{.Origin}}/rpc/2022-12-22", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      id: Date.now(),
      jsonrpc: "2.0",
      method: "save_for_later",
      params: {
        AuthKey: "{{.AuthKey}}",
        Title: document.title,
        URL: window.location.href,
        Note: prompt("Leave a note with this entry for later?"),
      },
    }),
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error("non-ok status returned (" + response.statusText + ")");
      }
      return response.json();
    })
    .then((data) => {
      if (data.jsonrpc !== "2.0") {
        throw new Error("invalid response structure");
      }
      if (data.error) {
        throw new Error(
          data.error.message + " (" + String(data.error.code) + ")"
        );
      }
    })
    .catch((reason) => {
      alert(`RSSLater: error: ${reason}`);
    });
})();
