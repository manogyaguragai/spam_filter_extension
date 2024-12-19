document.getElementById("analyze-btn").addEventListener("click", async () => {
  const emailContent = document.getElementById("email-content").value;
  const resultDiv = document.getElementById("result");

  if (!emailContent.trim()) {
    resultDiv.textContent = "Please enter email content.";
    return;
  }

  resultDiv.textContent = "Analyzing...";

  try {
    const response = await fetch("http://127.0.0.1:8000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ content: emailContent }),
    });

    const data = await response.json();
    if (data.is_spam) {
      resultDiv.textContent = `Spam: ${data.reason}`;
    } else {
      resultDiv.textContent = "Normal: Email appears legitimate.";
    }
  } catch (error) {
    resultDiv.textContent = "Error analyzing email.";
    console.error("Error:", error);
  }
});
