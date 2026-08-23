document.addEventListener('DOMContentLoaded', () => {
  // 1. Password Visibility Toggle
  const toggleBtns = document.querySelectorAll('.password-toggle-btn');
  toggleBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const group = btn.closest('.input-group') || btn.parentElement;
      const input = group ? group.querySelector('input') : null;
      if (input) {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        btn.innerHTML = isPassword ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
        btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
      }
    });
  });

  // 2. Real-time Password Strength Meter
  const regPasswordInput = document.getElementById('reg_password');
  const strengthBarFill = document.getElementById('strength_bar_fill');
  const strengthText = document.getElementById('strength_text');

  if (regPasswordInput && strengthBarFill && strengthText) {
    regPasswordInput.addEventListener('input', () => {
      const val = regPasswordInput.value;
      let score = 0;

      if (val.length >= 8) score += 25;
      if (/[A-Z]/.test(val)) score += 20;
      if (/[a-z]/.test(val)) score += 15;
      if (/\d/.test(val)) score += 20;
      if (/[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\/`~]/.test(val)) score += 20;

      strengthBarFill.style.width = score + '%';

      if (score === 0) {
        strengthBarFill.style.backgroundColor = 'transparent';
        strengthText.innerText = 'Requirements: 8+ chars, upper, lower, number, symbol';
        strengthText.style.color = '#64748b';
      } else if (score < 45) {
        strengthBarFill.style.backgroundColor = '#ef4444';
        strengthText.innerText = 'Weak password';
        strengthText.style.color = '#f87171';
      } else if (score < 80) {
        strengthBarFill.style.backgroundColor = '#fbbf24';
        strengthText.innerText = 'Moderate security';
        strengthText.style.color = '#fcd34d';
      } else {
        strengthBarFill.style.backgroundColor = '#34d399';
        strengthText.innerText = 'Strong & secure password';
        strengthText.style.color = '#6ee7b7';
      }
    });
  }

  // 3. 6-Box OTP Input Logic (Auto-advance, Backspace, Full Clipboard Paste)
  const otpInputs = document.querySelectorAll('.otp-digit');
  const otpForm = document.getElementById('otp_form');

  if (otpInputs.length > 0) {
    // Focus first input automatically
    otpInputs[0].focus();

    otpInputs.forEach((input, index) => {
      // Keydown handler (for backspace, arrows)
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !input.value && index > 0) {
          otpInputs[index - 1].focus();
        } else if (e.key === 'ArrowLeft' && index > 0) {
          otpInputs[index - 1].focus();
        } else if (e.key === 'ArrowRight' && index < otpInputs.length - 1) {
          otpInputs[index + 1].focus();
        }
      });

      // Input handler for numeric validation and auto-advance
      input.addEventListener('input', (e) => {
        const val = input.value.replace(/\D/g, ''); // keep only numbers
        input.value = val.slice(0, 1);

        if (input.value && index < otpInputs.length - 1) {
          otpInputs[index + 1].focus();
        }

        // Auto submit when all 6 digits are filled
        const allFilled = Array.from(otpInputs).every(inp => inp.value.length === 1);
        if (allFilled && otpForm) {
          // Optional subtle delay before submitting for smooth animation
          setTimeout(() => {
            otpForm.submit();
          }, 200);
        }
      });

      // Paste handler for pasting entire 6-digit code
      input.addEventListener('paste', (e) => {
        e.preventDefault();
        const pastedData = (e.clipboardData || window.clipboardData).getData('text');
        const digits = pastedData.replace(/\D/g, '').slice(0, 6);

        if (digits.length > 0) {
          digits.split('').forEach((char, i) => {
            if (i < otpInputs.length) {
              otpInputs[i].value = char;
            }
          });

          const nextIndex = Math.min(digits.length, otpInputs.length - 1);
          otpInputs[nextIndex].focus();

          if (digits.length === 6 && otpForm) {
            setTimeout(() => {
              otpForm.submit();
            }, 200);
          }
        }
      });
    });
  }

  // 4. Copy-to-Clipboard for TOTP Secret Key
  const copySecretBtn = document.getElementById('copy_secret_btn');
  const secretKeyText = document.getElementById('secret_key_text');

  if (copySecretBtn && secretKeyText) {
    copySecretBtn.addEventListener('click', () => {
      const textToCopy = secretKeyText.innerText.trim();
      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalHtml = copySecretBtn.innerHTML;
        copySecretBtn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
        copySecretBtn.classList.add('badge-success');
        setTimeout(() => {
          copySecretBtn.innerHTML = originalHtml;
          copySecretBtn.classList.remove('badge-success');
        }, 2000);
      });
    });
  }

  // 5. Auto dismiss flash alerts after 6 seconds
  const alerts = document.querySelectorAll('.alert');
  alerts.forEach(alert => {
    const closeBtn = alert.querySelector('.alert-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        alert.remove();
      });
    }
    setTimeout(() => {
      alert.style.transition = 'opacity 0.5s ease';
      alert.style.opacity = '0';
      setTimeout(() => alert.remove(), 500);
    }, 6000);
  });
});
