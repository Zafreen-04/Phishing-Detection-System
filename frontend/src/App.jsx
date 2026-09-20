import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const checkURL = async () => {
    if (!url.trim()) {
      setError("Please enter a URL");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch("http://127.0.0.1:5000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: url.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Something went wrong");
      }

      setResult(data);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  };

  return (
    <div className="app">

      <header className="navbar">
        <h2>🛡️ Phishing Detection System</h2>
      </header>

      <main className="container">

        <section className="hero">
          <h1>Phishing Website Detection</h1>

          <p>
            Check whether a website URL is legitimate or potentially
            phishing using machine learning.
          </p>

          <div className="search-box">

            <input
              type="text"
              placeholder="Enter website URL..."
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setResult(null);
                setError("");
              }}
            />

            <button onClick={checkURL} disabled={loading}>
              {loading ? "Checking..." : "Check URL"}
            </button>

          </div>

          {error && (
            <div className="error">
              {error}
            </div>
          )}

        </section>


        {result && (
          <section className="result-card">

            <h2>Detection Result</h2>

            <p className="checked-url">
              <strong>URL:</strong> {result.url}
            </p>

            <div
              className={
                result.result === "Phishing"
                  ? "result phishing"
                  : "result legitimate"
              }
            >
              {result.result === "Phishing"
                ? "⚠️ Phishing Website"
                : "✅ Legitimate Website"}
            </div>

            <div className="confidence">
              <strong>Confidence:</strong>{" "}
              {result.confidence}%
            </div>


            <div className="reasons">

              <h3>Detection Reasons</h3>

              <ul>
                {result.reasons.map((reason, index) => (
                  <li key={index}>
                    {reason}
                  </li>
                ))}
              </ul>

            </div>

          </section>
        )}

      </main>

    </div>
  );
}

export default App;