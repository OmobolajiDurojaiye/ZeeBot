"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const signupBtn = document.getElementById("signup-btn");
  const loginBtn = document.getElementById("login-btn");
  const signupForm = document.getElementById("signup-form");
  const loginForm = document.getElementById("login-form");
  const termsLink = document.getElementById("terms-link");
  const modal = document.getElementById("terms-modal");
  const closeModal = document.querySelector(".close");

  signupBtn.addEventListener("click", () => {
    signupForm.classList.add("active");
    loginForm.classList.remove("active");
    signupBtn.classList.add("active");
    loginBtn.classList.remove("active");
  });

  loginBtn.addEventListener("click", () => {
    loginForm.classList.add("active");
    signupForm.classList.remove("active");
    loginBtn.classList.add("active");
    signupBtn.classList.remove("active");
  });

  termsLink.addEventListener("click", () => {
    modal.style.display = "block";
  });

  closeModal.addEventListener("click", () => {
    modal.style.display = "none";
  });

  window.addEventListener("click", (event) => {
    if (event.target == modal) {
      modal.style.display = "none";
    }
  });
});
