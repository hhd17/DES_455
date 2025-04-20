const $ = (id) => document.getElementById(id);
const API = window.location.origin;

const isHex = (str) => /^[0-9a-fA-F]+$/.test(str);
const clearErrors = () => {
    $("msgErr").textContent = "";
    $("keyErr").textContent = "";
};

const disableButtons = (disabled) => {
    $("encBtn").disabled = $("decBtn").disabled = disabled;
};

const writeResult = (text) => ($("result").textContent = text);

const renderList = (containerId, title, items, className) => {
    const box = $(containerId);
    box.innerHTML = items.length ? `<h4>${title}</h4>` : "";
    items.forEach((item, i) => {
        box.innerHTML += `<div class="${className}">Round ${i + 1}: ${item}</div>`;
    });
};

async function fetchDES(endpoint, payload) {
    const response = await fetch(`${API}/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (data.error) throw new Error(data.error);
    return data;
}

async function handleEncrypt() {
    clearErrors();
    const message = $("message").value.trim();
    const key = $("hexKey").value.trim().toLowerCase();
    const mode = $("mode").value;

    if (!message) {
        $("msgErr").textContent = "Message required";
        return;
    }
    if (!isHex(key) || key.length !== 16) {
        $("keyErr").textContent = "Key must be 16‑char hex";
        return;
    }

    disableButtons(true);
    try {
        const result = await fetchDES("encrypt", {
            message,
            hex_key: key,
            mode,
        });
        writeResult(`Encrypted (hex):\n${result.encrypted_hex}`);
        renderList("roundBox", "Round Results", result.round_results, "round");
        renderList("keyBox", "Key Expansions", result.key_expansions, "key");
    } catch (e) {
        writeResult(`Error: ${e.message}`);
        renderList("roundBox", "", [], "round");
        renderList("keyBox", "", [], "key");
    } finally {
        disableButtons(false);
    }
}

async function handleDecrypt() {
    clearErrors();
    const hexMsg = $("message").value.trim().toLowerCase();
    const key = $("hexKey").value.trim().toLowerCase();
    const mode = $("mode").value;

    if (!hexMsg || !isHex(hexMsg)) {
        $("msgErr").textContent = "Valid hex required";
        return;
    }
    if (!isHex(key) || key.length !== 16) {
        $("keyErr").textContent = "Key must be 16‑char hex";
        return;
    }

    disableButtons(true);
    try {
        const result = await fetchDES("decrypt", {
            hex_message: hexMsg,
            hex_key: key,
            mode,
        });
        writeResult(
            `Decrypted (utf‑8):\n${result.decrypted_text}\n\nHex:\n${result.decrypted_hex}`
        );
        renderList("roundBox", "Round Results", result.round_results, "round");
        renderList("keyBox", "Key Expansions", result.key_expansions, "key");
    } catch (e) {
        writeResult(`Error: ${e.message}`);
        renderList("roundBox", "", [], "round");
        renderList("keyBox", "", [], "key");
    } finally {
        disableButtons(false);
    }
}

function getCookie(name) {
    return (
        document.cookie
            .split("; ")
            .find((row) => row.startsWith(name + "="))
            ?.split("=")[1] || null
    );
}

(function initAuth() {
    const token = getCookie("token");
    const box = $("authLinks");

    if (!token) {
        box.innerHTML = `<a href="/login">Login</a><a href="/register">Register</a>`;
        return;
    }

    try {
        const payload = JSON.parse(atob(token.split(".")[1] || ""));
        const user = payload.username || "User";
        box.innerHTML = `
          <span>Welcome, ${user}</span>
          <a href="/history">History</a>
          <a href="/logout">Logout</a>
        `;
    } catch {
        box.textContent = "";
    }
})();
