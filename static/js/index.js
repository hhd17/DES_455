const $ = (id) => document.getElementById(id);
const extraField = $("extraParam");
const extraLabel = $("extraLabel");
const extraError = $("extraErr");
const generatedExtraBox = $("generatedExtra");
const extraOutput = $("extraOutput");
const API = window.location.origin;

const isHex = (str) => /^[0-9a-fA-F]+$/.test(str);
const clearErrors = () => {
    $("msgErr").textContent = "";
    $("keyErr").textContent = "";
};
$("mode").addEventListener("change", () => {
    updateExtraFieldVisibility();
});
$("operation").addEventListener("change", updateExtraFieldVisibility);
const disableButtons = (disabled) => {
    $("submitBtn").disabled = disabled;
};
document.addEventListener("DOMContentLoaded", updateExtraFieldVisibility);

const writeResult = (text) => ($("result").textContent = text);

const renderList = (containerId, title, items, className) => {
    const box = $(containerId);
    box.innerHTML = items.length ? `<h4>${title}</h4>` : "";

    items.forEach((item, i) => {
        box.innerHTML += `<div class="${className}">Round ${i + 1}: ${item}</div>`;
    });

    // Inject button ONLY inside keyBox
    if (containerId === "keyBox") {
        box.innerHTML += `
            <div class="mt-4 text-center" id="viewDetailsBtn" style="display: none;">
                <a href="/des/details" class="btn btn-primary">
                       View Round 1 & Key Details
                </a>
            </div>
        `;
    }
};

function updateExtraFieldVisibility() {
    const mode = $("mode").value;
    const operation = $("operation").value;

    const shouldShow = operation === "decrypt" && mode !== "ECB";

    // Toggle visibility
    extraField.style.display = shouldShow ? "block" : "none";
    extraLabel.style.display = shouldShow ? "block" : "none";

    // Optional: disable/enable field when shown
    extraField.disabled = !shouldShow;

    // Optional: reset field if not needed
    if (!shouldShow) {
        extraField.value = "";
        extraError.textContent = "";
    }
}

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

function handleSubmit() {
    const operation = document.getElementById('operation').value;
    if (operation === 'encrypt') {
      handleEncrypt();
    } else {
      handleDecrypt();
    }
  }

async function handleEncrypt() {
    clearErrors();
    updateExtraFieldVisibility();
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
        if (result.extra) {
            generatedExtraBox.style.display = "block";
            extraOutput.textContent = result.extra;
        } else {
            generatedExtraBox.style.display = "none";
            extraOutput.textContent = "";
        }
        renderList("roundBox", "Round Results", result.round_results, "round");
        renderList("keyBox", "Key Expansions", result.key_expansions, "key");
    } catch (e) {
        writeResult(`Error: ${e.message}`);
        renderList("roundBox", "", [], "round");
        renderList("keyBox", "", [], "key");
    } finally {
        disableButtons(false);
    }
    document.getElementById("viewDetailsBtn").style.display = "block";
}

async function handleDecrypt() {
    clearErrors();
    updateExtraFieldVisibility();
    const hexMsg = $("message").value.trim().toLowerCase();
    const key = $("hexKey").value.trim().toLowerCase();
    const mode = $("mode").value;
    const payload = { hex_message: hexMsg, hex_key: key, mode };
    if (!hexMsg || !isHex(hexMsg)) {
        $("msgErr").textContent = "Valid hex required";
        return;
    }
    if (!isHex(key) || key.length !== 16) {
        $("keyErr").textContent = "Key must be 16‑char hex";
        return;
    }
    if (mode !== "ECB") {
        const extra = extraField.value.trim();
        if (!isHex(extra)) {
            extraError.textContent =
                "IV / nonce / counter is required and must be hex.";
            return;
        }
        payload.extra = extra;
    }
    disableButtons(true);
    try {
        const result = await fetchDES("decrypt", payload);
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
    document.getElementById("viewDetailsBtn").style.display = "block";
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
        const payload = JSON.parse(atob(token.split(".")[1] || "{}"));
        const uid = payload.user_id;
        const pic = `/avatar/${uid}`;
        box.innerHTML = `
  <a href="/profile"><img src="${pic}" class="avatar-thumb" alt="profile"></a>
`;
    } catch {
        box.textContent = "";
    }
})();
