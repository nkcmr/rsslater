import { useCallback, useEffect, useState } from "/lib/hooks.module.js";
import { h, render } from "/lib/preact.module.js";

function browserAPI() {
  return globalThis.browser || globalThis.chrome;
}

function storageAPI() {
  return browserAPI().storage.local;
}

function isFirefox() {
  return (
    /Firefox\/[0-9\.]+/.test(navigator.userAgent) &&
    !/Seamonkey\//.test(navigator.userAgent)
  );
}

const checkConnection = () => {
  return new Promise((resolve, reject) => {
    storageAPI().get(["jwt", "endpoint"], (data) => {
      if (browserAPI().runtime.lastError) {
        reject(new Error(browserAPI().runtime.lastError.message));
        return;
      }
      if (!data.jwt || !data.endpoint) {
        resolve(null);
      } else {
        resolve(data);
      }
    });
  });
};

function getActiveTab() {
  return new Promise((resolve, reject) => {
    browserAPI().tabs.query({ active: true }, (tabs) => {
      if (browserAPI().runtime.lastError) {
        reject(new Error(browserAPI().runtime.lastError.message));
        return;
      }
      resolve(tabs[0]);
    });
  });
}

const submitEntry = async ({ connection, note }) => {
  const activeTab = await getActiveTab();
  const { url, title } = activeTab;
  const response = await fetch(connection.endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      id: Date.now(),
      jsonrpc: "2.0",
      method: "save_for_later",
      params: {
        AuthKey: connection.jwt,
        Title: title,
        URL: url,
        Note: note,
      },
    }),
  });
  if (!response.ok) {
    throw new Error("non-ok status returned (" + response.statusText + ")");
  }
  const data = await response.json();
  if (data.jsonrpc !== "2.0") {
    throw new Error("invalid response structure");
  }
  if (data.error) {
    throw new Error(data.error.message + " (" + String(data.error.code) + ")");
  }
};

const EntryForm = () => {
  const [pairingCode, setPairingCode] = useState("");
  useEffect(() => {
    if (pairingCode.length > 0) {
      try {
        console.log("attempting to set connection");
        const newConnection = JSON.parse(atob(pairingCode));
        if (!newConnection.jwt || !newConnection.endpoint) {
          return;
        }
        console.log("attempting to set connection", newConnection);

        storageAPI()
          .clear()
          .then(() => {
            console.log("storage cleared");
            return storageAPI().set(newConnection);
          })
          .catch(() => {});
      } catch (e) {}
    }
  }, [pairingCode]);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const [error, setError] = useState(null);
  useEffect(() => {
    if (error) {
      setTimeout(() => {
        setError(null);
      }, 5000);
    }
  }, [error, setError]);
  const [entryJustSubmitted, setEntryJustSubmitted] = useState(false);
  useEffect(() => {
    if (entryJustSubmitted) {
      setTimeout(() => {
        window.close();
      }, 1250);
    }
  }, [entryJustSubmitted, setEntryJustSubmitted]);
  const [connection, setConnection] = useState(null);
  const doSubmit = useCallback(
    (e) => {
      console.log({ connection, note });
      e.preventDefault();
      setBusy(true);
      submitEntry({ connection, note })
        .then(() => {
          setEntryJustSubmitted(true);
        })
        .catch((err) => {
          setError(`${err}`);
        })
        .finally(() => {
          setBusy(false);
        });
    },
    [note, connection]
  );
  useEffect(() => {
    checkConnection().then(setConnection);
    storageAPI().onChanged.addListener(() => {
      checkConnection().then(setConnection);
    });
  }, [setConnection]);
  const renderErr = !connection
    ? "Please connect the extension to an RSSLater server"
    : error !== null
    ? error
    : false;
  return h("div", null, [
    h(
      "h4",
      {
        style: "margin-top: 0; margin-bottom: 0.5em",
      },
      "RSSLater"
    ),
    isFirefox() && !connection
      ? h("div", null, [
          h(
            "div",
            {
              style: "padding: 0.5em; background-color: #0078e7; color: white;",
            },
            "Enter the manual pairing code from the RSSLater control panel below:"
          ),
          h("form", { className: "pure-form" }, [
            h(
              "label",
              {
                htmlFor: "pairing-code",
              },
              "Manual Pairing Code"
            ),
            h("input", {
              id: "pairing-code",
              type: "text",
              value: pairingCode,
              onInput: (e) => {
                setPairingCode(e.target.value);
              },
            }),
          ]),
        ])
      : null,
    !renderErr
      ? null
      : h(
          "div",
          {
            style:
              "padding: 0.5em; background-color: rgb(202, 60, 60); color: white;",
          },
          [h("b", null, "ERROR: "), renderErr]
        ),

    h(
      "form",
      {
        id: "sfl-form",
        className: "pure-form pure-form-stacked",
        onSubmit: doSubmit,
      },
      [
        h("formset", null, [
          h("legend", null, "Save this page to your read later feed"),
          h("label", { htmlFor: "entry-note" }, "Note"),
          h("input", {
            type: "text",
            className: "pure-input-1",
            name: "note",
            id: "entry-note",
            value: note,
            onInput: (e) => {
              console.log(e.target.value);
              setNote(e.target.value);
            },
          }),
          h(
            "button",
            {
              type: "submit",
              class: "pure-button pure-button-primary",
              disabled: !connection || busy || entryJustSubmitted,
            },
            entryJustSubmitted ? "Saved!" : "Save"
          ),
        ]),
      ]
    ),
  ]);
};

const App = h(EntryForm, null);

render(App, document.body);
