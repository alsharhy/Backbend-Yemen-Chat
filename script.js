// script.js

let chats = [];
let currentChatId = null;
let apiKey = localStorage.getItem('apiKey') || "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";

function generateId() {
  return Math.random().toString(36).substr(2, 9);
}

function formatTime(date = new Date()) {
  return date.toLocaleTimeString('ar-EG', { hour: '2-digit', minute: '2-digit' });
}

function checkAPIStatus() {
  fetch("https://openrouter.ai/api/v1/models")
    .then(response => {
      if (!response.ok) {
        console.error("مشكلة في اتصال OpenRouter API");
      } else {
        console.log("اتصال API يعمل بشكل صحيح");
      }
    })
    .catch(error => console.error("فشل الاتصال بـ OpenRouter:", error));
}

document.addEventListener("DOMContentLoaded", () => {
  checkAPIStatus();
  initEmojis();

  document.addEventListener("click", function (event) {
    const sidebar = document.getElementById("sidebar");
    const dropdown = document.getElementById("dropdown");
    const settingsModal = document.getElementById("settings-modal");
    const emojiContainer = document.getElementById("emoji-container");
    const menuBtn = document.querySelector(".header-btn");
    const plusBtn = document.querySelector(".fa-paperclip").closest(".input-btn");
    const emojiBtn = document.querySelector(".fa-smile").closest(".input-btn");

    if (sidebar.classList.contains("visible") && !sidebar.contains(event.target) && !menuBtn.contains(event.target)) {
      sidebar.classList.remove("visible");
    }

    if (dropdown.style.display === "flex" && !dropdown.contains(event.target) && !plusBtn.contains(event.target)) {
      dropdown.style.display = "none";
    }

    if (settingsModal.style.display === "flex" && event.target === settingsModal) {
      closeSettings();
    }

    if (emojiContainer.style.display === "block" && !emojiContainer.contains(event.target) && !emojiBtn.contains(event.target)) {
      emojiContainer.style.display = "none";
    }
  });

  loadProfile();
});

function toggleSidebar() {
  document.getElementById("sidebar").classList.toggle("visible");
}

function togglePlusMenu() {
  const dropdown = document.getElementById("dropdown");
  dropdown.style.display = dropdown.style.display === "flex" ? "none" : "flex";
}

function toggleEmojiPicker() {
  const emojiContainer = document.getElementById("emoji-container");
  emojiContainer.style.display = emojiContainer.style.display === "block" ? "none" : "block";
}

function initEmojis() {
  const picker = document.getElementById('emoji-picker');
  if (picker) {
    picker.addEventListener('emoji-click', event => {
      document.getElementById("prompt").value += event.detail.unicode;
      document.getElementById("emoji-container").style.display = "none";
    });
  }
}

function openSettings() {
  document.getElementById('settings-modal').style.display = 'flex';
  document.getElementById('api-key').value = apiKey;
  showProfileSettings();
}

function closeSettings() {
  document.getElementById('settings-modal').style.display = 'none';
}

function showProfileSettings() {
  document.getElementById('profile-settings').style.display = 'block';
  document.getElementById('api-settings').style.display = 'none';
}

function showApiSettings() {
  document.getElementById('profile-settings').style.display = 'none';
  document.getElementById('api-settings').style.display = 'block';
}

function promptForImage() {
  const url = prompt("أدخل رابط الصورة:");
  if (url) {
    const img = document.getElementById('profile-image');
    img.src = url;
    img.style.display = 'block';
    document.getElementById('plus-icon').style.display = 'none';
  }
}

function saveSettings() {
  localStorage.setItem("fullName", document.getElementById("full-name").value);
  localStorage.setItem("username", document.getElementById("username").value);
  localStorage.setItem("email", document.getElementById("email").value);
  localStorage.setItem("profileImage", document.getElementById("profile-image").src);
  apiKey = document.getElementById('api-key').value;
  localStorage.setItem('apiKey', apiKey);
  closeSettings();
  alert("تم حفظ الإعدادات بنجاح!");
}

function loadProfile() {
  document.getElementById("full-name").value = localStorage.getItem("fullName") || "";
  document.getElementById("username").value = localStorage.getItem("username") || "";
  document.getElementById("email").value = localStorage.getItem("email") || "";
  const img = localStorage.getItem("profileImage");
  if (img) {
    document.getElementById("profile-image").src = img;
    document.getElementById("profile-image").style.display = 'block';
    document.getElementById("plus-icon").style.display = 'none';
  }
}

function copyCode(button) {
  const code = button.closest('.code-header').nextElementSibling.textContent;
  navigator.clipboard.writeText(code).then(() => {
    const originalText = button.innerHTML;
    button.innerHTML = 'تم النسخ!';
    setTimeout(() => {
      button.innerHTML = originalText;
    }, 2000);
  });
}

function copyMessage(button) {
  const msg = button.closest('.message').querySelector('.message-content').innerText;
  navigator.clipboard.writeText(msg).then(() => {
    const original = button.innerHTML;
    button.innerHTML = '<i class="fas fa-check"></i>';
    setTimeout(() => button.innerHTML = '<i class="fas fa-copy"></i>', 2000);
  });
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatMessageContent(content) {
  if (/```[\s\S]*?```/.test(content)) {
    const codeBlocks = content.match(/```(\w*)\n([\s\S]*?)```/g);
    let formattedContent = content;

    codeBlocks.forEach((block) => {
      const langMatch = block.match(/```(\w*)\n/);
      const lang = langMatch ? langMatch[1] : 'text';
      const codeText = block.replace(/```(\w*)\n/, '').replace(/```$/, '');

      const codeBlock = `
        <div style="position: relative; margin: 15px 0;">
          <div class="code-header">
            <span class="language-tag">${lang}</span>
            <button class="copy-btn" onclick="copyCode(this)">
              <i class="fas fa-copy"></i> نسخ الكود
            </button>
          </div>
          <pre><code class="language-${lang}">${escapeHtml(codeText)}</code></pre>
        </div>
      `;

      formattedContent = formattedContent.replace(block, codeBlock);
    });

    return formattedContent;
  }

  return content.replace(/\n/g, '<br>');
}

function renderMessages() {
  const chatWindow = document.getElementById("chat-window");
  const chat = chats.find((c) => c.id === currentChatId);
  if (!chat || chat.messages.length === 0) {
    chatWindow.innerHTML = document.querySelector('.welcome-message').outerHTML;
    return;
  }
  chatWindow.innerHTML = "";
  chat.messages.forEach((msg) => {
    const div = document.createElement("div");
    div.className = `message ${msg.role}`;
    if (msg.role === 'assistant' && msg.content === "جارٍ الكتابة...") {
      div.className = "message bot";
      div.innerHTML = `
        <div class="typing-indicator">
          <span></span><span></span><span></span>
        </div>`;
    } else {
      div.innerHTML = `
        <div class="message-header">
          <div class="message-sender">
            ${msg.role === 'user' ? 'You' : 'Taiz Soft'}
          </div>
          <div class="message-time">${formatTime(msg.timestamp)}</div>
        </div>
        <div class="message-content">${formatMessageContent(msg.content)}</div>`;
    }
    chatWindow.appendChild(div);
  });
  chatWindow.scrollTop = chatWindow.scrollHeight;
  if (typeof hljs !== 'undefined') {
  document.querySelectorAll('pre code').forEach((block) => {
    hljs.highlightElement(block);
  });
}
}

function sendMessage(customPrompt = null) {
  const input = document.getElementById("prompt");
  const prompt = customPrompt || input.value.trim();
  if (!prompt) return;
  input.value = "";

  if (!currentChatId) startNewChat();
  const chat = chats.find((c) => c.id === currentChatId);
  chat.messages.push({ role: "user", content: prompt, timestamp: new Date() });
  renderMessages();

  const typingMsg = { role: "assistant", content: "جارٍ الكتابة...", timestamp: new Date() };
  chat.messages.push(typingMsg);
  renderMessages();

  const payloadMessages = chat.messages
    .filter(m => !(m.role === 'assistant' && m.content === "جارٍ الكتابة..."))
    .map(({ role, content }) => ({ role, content }));

  fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`,
      "X-Title": "AI Chat"
    },
    body: JSON.stringify({
      model: "openai/gpt-4o",
      messages: payloadMessages,
      max_tokens: 1000
    }),
  })
    .then(response => {
      if (!response.ok) {
        return response.json().then(err => { throw new Error(JSON.stringify(err)) });
      }
      return response.json();
    })
    .then(data => {
      chat.messages.pop();
      const content = data.choices?.[0]?.message?.content || "لم أتمكن من إيجاد رد مناسب.";
      chat.messages.push({ role: "assistant", content, timestamp: new Date() });

      if (chat.title === "محادثة جديدة") {
        chat.title = content.slice(0, 30) + (content.length > 30 ? "..." : "");
        updateChatList();
      }

      renderMessages();
    })
    .catch(error => {
      console.error("Error:", error);
      chat.messages.pop();

      let errorMsg = "حدث خطأ أثناء جلب الرد. يرجى المحاولة مرة أخرى.";
      try {
        const errorData = JSON.parse(error.message);
        if (errorData.error && errorData.error.message) {
          errorMsg = errorData.error.message;
        }
      } catch (e) {
        if (error.message.includes("401")) {
          errorMsg = "مفتاح API غير صحيح أو منتهي الصلاحية";
        } else if (error.message.includes("402")) {
          errorMsg = "انتهى رصيدك في OpenRouter";
        } else if (error.message.includes("404")) {
          errorMsg = "نقطة النهاية غير صحيحة";
        }
      }

      chat.messages.push({ role: "assistant", content: errorMsg, timestamp: new Date() });
      renderMessages();
    });
}

function startNewChat() {
  const newChat = {
    id: generateId(),
    title: "محادثة جديدة",
    messages: [],
  };
  chats.push(newChat);
  currentChatId = newChat.id;
  updateChatList();
  renderMessages();
}

function updateChatList() {
  const chatList = document.getElementById("chat-list");
  chatList.innerHTML = "";
  chats.forEach(chat => {
    const li = document.createElement("li");
    li.className = chat.id === currentChatId ? "active" : "";
    li.innerHTML = `
      <div class="chat-info">
        <i class="fas fa-comment chat-icon"></i>
        <span>${chat.title}</span>
      </div>
      <button class="delete-chat" onclick="deleteChat(event, '${chat.id}')">
        <i class="fas fa-trash"></i>
      </button>
    `;
    li.addEventListener("click", () => {
      currentChatId = chat.id;
      updateChatList();
      renderMessages();
    });
    chatList.appendChild(li);
  });
}

function deleteChat(event, id) {
  event.stopPropagation();
  chats = chats.filter(chat => chat.id !== id);
  if (currentChatId === id) {
    currentChatId = chats.length > 0 ? chats[0].id : null;
  }
  updateChatList();
  renderMessages();
}

function uploadFile(type) {
  alert(`تم اختيار رفع ملف من نوع: ${type}. هذه ميزة تجريبية، سيتم تنفيذها بالكامل في المستقبل.`);
  togglePlusMenu();
}