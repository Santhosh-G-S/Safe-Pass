(function () {
    const chatBox = document.getElementById("chat-container");
    const form    = document.getElementById("chat-form");
    const input   = document.getElementById("inputLarge");

    // Configure marked.js
    marked.setOptions({ breaks: true, gfm: true });

    // ── Message rendering ─────────────────────────────────────

    function addMessage(sender, text, isTyping = false) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'd-flex mb-3 message-appear';

        if (sender === 'You') {
            messageDiv.classList.add('justify-content-end');
            const escaped = text
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
            messageDiv.innerHTML = `
                <div class="bg-primary text-white rounded-3 p-3 shadow-sm" style="max-width:75%;">
                    <strong class="d-block mb-1">You</strong>
                    <span>${escaped}</span>
                </div>`;
        } else {
            if (isTyping) {
                messageDiv.innerHTML = `
                    <div class="rounded-3 p-3 shadow-sm"
                         style="max-width:75%; background:rgba(255,255,255,0.25);
                                backdrop-filter:blur(10px); border:1px solid rgba(255,255,255,0.4);">
                        <strong class="d-block mb-1 text-primary">AI Assistant</strong>
                        <div class="typing-indicator">
                            <span></span><span></span><span></span>
                        </div>
                    </div>`;
            } else {
                messageDiv.innerHTML = `
                    <div class="rounded-3 p-3 shadow-sm"
                         style="max-width:75%; background:rgba(255,255,255,0.25);
                                backdrop-filter:blur(10px); border:1px solid rgba(255,255,255,0.4);">
                        <strong class="d-block mb-2 text-primary">AI Assistant</strong>
                        <div style="color:#333;">${marked.parse(text)}</div>
                    </div>`;
            }
        }

        chatBox.appendChild(messageDiv);
        chatBox.scrollTop = chatBox.scrollHeight;
        return messageDiv;
    }

    // ── API call ──────────────────────────────────────────────

    async function sendToBackend(text, typingElement) {
        try {
            const res  = await fetch('/api/v1/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_input: text })
            });

            const data = await res.json();
            if (typingElement) typingElement.remove();

            if (!res.ok) {
                addMessage('AI', 'Sorry, I encountered an error. Please try again.');
                return;
            }

            addMessage('AI', data.data.reply || "I didn't receive a response. Please try again.");

        } catch (err) {
            if (typingElement) typingElement.remove();
            addMessage('AI', 'Network error. Please check your connection and try again.');
        }
    }

    // ── Event listeners ───────────────────────────────────────

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        const userText = input.value.trim();
        if (!userText) return;

        addMessage('You', userText);
        input.value = '';

        const typingElement = addMessage('AI', '', true);
        sendToBackend(userText, typingElement);
    });

    input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            form.requestSubmit();
        }
    });

    input.focus();
})();
