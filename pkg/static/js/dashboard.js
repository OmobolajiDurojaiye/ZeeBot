"use strict";

const hamburger = document.querySelector(".hamburger");
const sidebar = document.querySelector(".sidebar");
hamburger.addEventListener("click", () => {
  sidebar.classList.toggle("active");
});

document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("walletForm");
  const resultMessage = document.getElementById("result-message");
  const connectButton = document.querySelector(".connectButton");
  const numberConnected = document.querySelector(".numberConnected");
  let counter = 0;

  // Form submission logic
  form.addEventListener("submit", async function (event) {
    event.preventDefault(); // Prevent the default form submission

    // Collect form data
    const formData = new FormData(form);
    const data = {
      api_key: formData.get("api_key"),
      api_secret: formData.get("api_secret"),
      csrf_token: formData.get("csrf_token"),
    };

    // Validate that the API key and secret are present
    if (!data.api_key || !data.api_secret) {
      resultMessage.style.display = "block";
      resultMessage.innerHTML = "API key and secret are required.";
      resultMessage.style.color = "red";
      return;
    }

    try {
      // Send POST request using Fetch API
      const response = await fetch('{{ url_for("connect_wallet") }}', {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": data.csrf_token,
        },
        body: JSON.stringify({
          api_key: data.api_key,
          api_secret: data.api_secret,
        }),
      });

      // Parse the response
      const result = await response.json();

      // Show the result message
      resultMessage.style.display = "block";
      resultMessage.innerHTML = result.message;

      // Optionally, add styling based on success or error
      if (result.success) {
        resultMessage.style.color = "green";

        // Increment the wallet connected counter on successful connection
        counter++;
        numberConnected.textContent = counter;

        // Redirect to wallet_control.html after a short delay
        setTimeout(() => {
          window.location.href = "{{ url_for('wallet_control') }}";
        }, 2000); // Adjust delay as needed
      } else {
        resultMessage.style.color = "red";
      }
    } catch (error) {
      // Handle any errors (e.g., network issues)
      resultMessage.style.display = "block";
      resultMessage.innerHTML = "An error occurred. Please try again.";
      resultMessage.style.color = "red";
    }
  });

  connectButton?.addEventListener("click", function () {
    counter++;
    numberConnected.textContent = counter;
  });
});

// Sidebar Navigation Items
const leverageItem = document.getElementById("leverage");
// const referFriendItem = document.getElementById("refer-friend");
const symbolItem = document.getElementById("symbol-select");
const tradeAmountItem = document.getElementById("trade-amount");
const bottomSection = document.querySelector(".bottom-section");

function displayFlashedMessage(message, category) {
  const flashContainer = document.getElementById("flash-messages");
  const alertDiv = document.createElement("div");
  alertDiv.className = `alert alert-${category} alert-dismissible fade show`;
  alertDiv.role = "alert";
  alertDiv.innerHTML = `
              ${message}
              <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                  <span aria-hidden="true">&times;</span>
              </button>
          `;
  flashContainer.appendChild(alertDiv);
}

leverageItem.addEventListener("click", function () {
  bottomSection.innerHTML = `
        <div id="flash-messages"></div>
          <form method="POST" action="/select-leverage" class="token-form" id="leverageForm">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="form-group">
              <label for="rangeInput">Select your leverage (1-10):</label>
              <input type="range" class="form-control-range" id="rangeInput" name="leverage" min="1" max="10" value="1">
            </div>
            <div class="form-group">
              <label for="numberDisplay">Selected Leverage:</label>
              <input type="number" class="form-control" id="numberDisplay" value="1" readonly>
            </div>
            <button type="button" class="btn btn-primary" id="submitLeverage">Set Leverage</button>
          </form>
        `;

  document.getElementById("rangeInput").addEventListener("input", function () {
    document.getElementById("numberDisplay").value = this.value;
  });

  const csrfToken = document.querySelector('input[name="csrf_token"]').value;

  document
    .getElementById("submitLeverage")
    .addEventListener("click", function () {
      const leverage = document.getElementById("rangeInput").value;

      // Perform AJAX call to the backend to set leverage
      $.ajax({
        url: "/select-leverage",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({ leverage }),
        headers: {
          "X-CSRFToken": csrfToken, // Add CSRF token to the headers
        },
        success: function (response) {
          displayFlashedMessage(response.message, "success");
        },
        error: function (error) {
          displayFlashedMessage("Error setting leverage.", "danger");
        },
      });
    });
});

// referFriendItem.addEventListener("click", function () {
//   bottomSection.innerHTML = `
//           <div class="share-icons">
//             <div id="flash-messages"></div>
//             <h2>Refer a Friend</h2>
//             <p>Your referral code: <strong>{{ user.referral_code }}</strong></p>
//             <p>Friends who signed up using your code: <strong>{{ user.referral_count }}</strong></p>
//             <div class="share-icons">
//               <h3>Share your code:</h3>
//               <input type="text" id="referralLink" value="{{ url_for('auth', _external=True) }}?ref={{ user.referral_code }}" readonly>
//               <button onclick="copyReferralLink()">Copy Link</button>
//               <a href="https://twitter.com/share?text=Join ZeeCryptoBot and use my referral code {{ user.referral_code }}" target="_blank">
//                 <img src="{{ url_for('static', filename='icons/twitter.jpg') }}" alt="Twitter" />
//               </a>
//               <a href="https://facebook.com/sharer/sharer.php?u={{ url_for('auth', _external=True) }}?ref={{ user.referral_code }}" target="_blank">
//                 <img src="{{ url_for('static', filename='icons/facebook.png') }}" alt="Facebook" />
//               </a>
//               <a href="https://www.linkedin.com/shareArticle?mini=true&url={{ url_for('auth', _external=True) }}?ref={{ user.referral_code }}" target="_blank">
//                 <img src="{{ url_for('static', filename='icons/linkedin.png') }}" alt="LinkedIn" />
//               </a>
//             </div>
//           </div>
//         `;
// });

// function copyReferralLink() {
//   var copyText = document.getElementById("referralLink");
//   copyText.select();
//   copyText.setSelectionRange(0, 99999);
//   document.execCommand("copy");
//   alert("Copied the referral link: " + copyText.value);
// }

// Handle Amount to Trade with AJAX
tradeAmountItem.addEventListener("click", function () {
  bottomSection.innerHTML = `
          <div id="flash-messages"></div>
              <form method="POST" action="/set_amount" class="token-form" id="tradeForm">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <h2>Amount To Trade</h2>
              <div class="form-group">
                  <label for="tradeAmountInput">Enter the amount you want to trade:</label>
                  <input type="number" class="form-control" id="tradeAmountInput" value="10000" />
              </div>
              <button type="button" class="btn btn-primary" id="submitTradeAmount">Trade</button>
          </form>
          `;

  document
    .getElementById("submitTradeAmount")
    .addEventListener("click", function () {
      const csrfToken = document.querySelector(
        'input[name="csrf_token"]'
      ).value;
      const amount = document.getElementById("tradeAmountInput").value;

      // Perform AJAX call to send the trade amount to the backend
      $.ajax({
        url: "/set_amount",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({ amount }),
        headers: {
          "X-CSRFToken": csrfToken, // Add CSRF token to the headers
        },
        success: function (response) {
          displayFlashedMessage(response.message, "success");
        },
        error: function (error) {
          displayFlashedMessage("Error setting leverage.", "danger");
        },
      });
    });
});

symbolItem.addEventListener("click", function () {
  // Insert the form into the bottomSection
  bottomSection.innerHTML = `
    <div id="flash-messages"></div>
        <form id="symbolForm" class="token-form">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label for="symbol">Choose a symbol:</label>
            <select name="symbol" id="symbol" required class="wide-select"></select>
            <button type="submit" class="btn btn-primary">Set Symbol</button>
        </form>
    `;

  // Fetch the symbols for the dropdown
  fetch("/select-symbol")
    .then((response) => response.json())
    .then((data) => {
      const select = document.getElementById("symbol");
      data.forEach((symbol) => {
        const option = document.createElement("option");
        option.value = symbol.name;
        option.textContent = symbol.name;
        select.appendChild(option);
      });
    })
    .catch((error) => console.error("Error fetching symbols:", error));

  // Add event listener for form submission using AJAX
  const symbolForm = document.getElementById("symbolForm");
  symbolForm.addEventListener("submit", function (event) {
    event.preventDefault(); // Prevent the default form submission

    // Get the selected symbol from the form
    const selectedSymbol = document.getElementById("symbol").value;

    // Make an AJAX POST request to submit the selected symbol
    fetch("/select-symbol", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": document.querySelector("[name=csrf_token]").value,
      },
      body: JSON.stringify({
        symbol: selectedSymbol,
      }),
    })
      .then((response) => {
        if (response.ok) {
          return response.json();
        } else {
          throw new Error("Form submission failed");
        }
      })
      .then((data) => {
        alert(data.message);
      })
      .catch((error) => {
        console.error("Error during form submission:", error);
        alert("Error submitting symbol. Please try again.");
      });
  });
  document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("walletForm");
    const resultMessage = document.getElementById("result-message");
    const connectButton = document.querySelector(".connectButton");
    const changeButton = document.getElementById("changeCredentialsButton");
    const numberConnected = document.querySelector(".numberConnected");
    let counter = 0;

    // Form submission logic
    form?.addEventListener("submit", async function (event) {
      event.preventDefault(); // Prevent the default form submission

      // Collect form data
      const formData = new FormData(form);
      const data = {
        api_key: formData.get("api_key"),
        api_secret: formData.get("api_secret"),
        csrf_token: formData.get("csrf_token"),
      };

      // Validate that the API key and secret are present
      if (!data.api_key || !data.api_secret) {
        resultMessage.style.display = "block";
        resultMessage.innerHTML = "API key and secret are required.";
        resultMessage.style.color = "red";
        return;
      }

      try {
        // Send POST request using Fetch API
        const response = await fetch('{{ url_for("connect_wallet") }}', {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": data.csrf_token,
          },
          body: JSON.stringify({
            api_key: data.api_key,
            api_secret: data.api_secret,
          }),
        });

        // Parse the response
        const result = await response.json();

        // Show the result message
        resultMessage.style.display = "block";
        resultMessage.innerHTML = result.message;

        // Optionally, add styling based on success or error
        if (result.success) {
          resultMessage.style.color = "green";

          // Increment the wallet connected counter on successful connection
          counter++;
          numberConnected.textContent = counter;

          // Redirect to wallet_control.html after a short delay
          setTimeout(() => {
            window.location.href = "{{ url_for('wallet_control') }}";
          }, 2000); // Adjust delay as needed
        } else {
          resultMessage.style.color = "red";
        }
      } catch (error) {
        // Handle any errors (e.g., network issues)
        resultMessage.style.display = "block";
        resultMessage.innerHTML = "An error occurred. Please try again.";
        resultMessage.style.color = "red";
      }
    });

    // Change API credentials logic
    changeButton?.addEventListener("click", function () {
      // Show the form for changing API credentials
      bottomSection.innerHTML = `
          <form class="token-form" id="changeApiForm" method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}" />
            <h2>Change API Parameter</h2>
            <label for="api-key">API KEY</label>
            <input type="text" id="api-key" name="api_key" placeholder="1-16 characters" required />
            <label for="api-secret">API SECRET</label>
            <input type="text" id="api-secret" name="api_secret" placeholder="0.99-44.532.5343" required />
            <button type="submit" class="connectButton">Update API Credentials</button>
          </form>
        `;

      const changeForm = document.getElementById("changeApiForm");

      // Handle the change form submission
      changeForm.addEventListener("submit", async function (event) {
        event.preventDefault();

        const formData = new FormData(changeForm);
        const data = {
          api_key: formData.get("api_key"),
          api_secret: formData.get("api_secret"),
          csrf_token: formData.get("csrf_token"),
        };

        // Validate that the API key and secret are present
        if (!data.api_key || !data.api_secret) {
          resultMessage.style.display = "block";
          resultMessage.innerHTML = "API key and secret are required.";
          resultMessage.style.color = "red";
          return;
        }

        try {
          // Send POST request using Fetch API
          const response = await fetch(
            '{{ url_for("change_api_credentials") }}',
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": data.csrf_token,
              },
              body: JSON.stringify({
                api_key: data.api_key,
                api_secret: data.api_secret,
              }),
            }
          );

          // Parse the response
          const result = await response.json();

          // Show the result message
          resultMessage.style.display = "block";
          resultMessage.innerHTML = result.message;

          // Optionally, add styling based on success or error
          if (result.success) {
            resultMessage.style.color = "green";
            setTimeout(() => {
              window.location.reload(); // Reload page after successful update
            }, 2000);
          } else {
            resultMessage.style.color = "red";
          }
        } catch (error) {
          // Handle any errors (e.g., network issues)
          resultMessage.style.display = "block";
          resultMessage.innerHTML = "An error occurred. Please try again.";
          resultMessage.style.color = "red";
        }
      });
    });
  });
});
