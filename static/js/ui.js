// UI enhancements for eLMS
(function() {
  // Bootstrap tooltips
  try {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.forEach(function (tooltipTriggerEl) {
      try { new bootstrap.Tooltip(tooltipTriggerEl); } catch (e) {}
    });
  } catch (e) {}

  // Ripple effect on buttons and nav links
  function addRipple(e) {
    var el = e.currentTarget;
    if (!el) return;
    var rect = el.getBoundingClientRect();
    var ripple = document.createElement('span');
    ripple.className = 'ripple';
    var size = Math.max(rect.width, rect.height);
    ripple.style.width = ripple.style.height = size + 'px';
    ripple.style.left = (e.clientX - rect.left - size/2) + 'px';
    ripple.style.top = (e.clientY - rect.top - size/2) + 'px';
    el.classList.add('ripple-container');
    el.appendChild(ripple);
    setTimeout(function(){ if (ripple && ripple.parentNode) ripple.parentNode.removeChild(ripple); }, 600);
  }
  ['.btn', '.nav-link', '.list-group-item', '.card'].forEach(function(sel){
    document.querySelectorAll(sel).forEach(function(el){
      el.addEventListener('click', addRipple);
    });
  });

  // Password validation helpers (change/reset pages)
  var oldPassword = document.getElementById('oldPassword');
  var newPassword = document.getElementById('newPassword') || document.getElementById('new_password');
  var confirmPassword = document.getElementById('confirmPassword') || document.getElementById('confirm_password');
  var passwordMatchText = document.getElementById('passwordMatch');

  function updateNewPasswordValidity() {
    if (!newPassword || !oldPassword) return;
    if (oldPassword.value === newPassword.value) {
      newPassword.setCustomValidity('Old and new password cannot be same');
    } else {
      newPassword.setCustomValidity('');
    }
  }

  function updateConfirmPasswordValidity() {
    if (!newPassword || !confirmPassword) return;
    if (newPassword.value !== confirmPassword.value) {
      confirmPassword.setCustomValidity('Passwords do not match');
      if (passwordMatchText) {
        passwordMatchText.textContent = '✗ Passwords do not match';
        passwordMatchText.className = 'form-text text-danger';
      }
    } else {
      confirmPassword.setCustomValidity('');
      if (passwordMatchText) {
        passwordMatchText.textContent = '✓ Passwords match';
        passwordMatchText.className = 'form-text text-success';
      }
    }
  }

  if (newPassword) newPassword.addEventListener('input', function(){ updateNewPasswordValidity(); updateConfirmPasswordValidity(); });
  if (confirmPassword) confirmPassword.addEventListener('input', updateConfirmPasswordValidity);

  // Camera trigger for photo upload (student/faculty)
  document.addEventListener('DOMContentLoaded', function() {
    var cameraTrigger = document.getElementById('cameraTrigger');
    var photoInput = document.getElementById('photo');
    var previewImg = document.getElementById('profilePreview');

    if (cameraTrigger && photoInput) {
      cameraTrigger.addEventListener('click', function(e) {
        e.preventDefault();
        photoInput.click();
      });

      photoInput.addEventListener('change', function() {
        var file = photoInput.files && photoInput.files[0];
        if (!file) return;

        var typeOk = /^(image\/(gif|jpeg|png|webp|jpg))$/i.test(file.type || '');
        if (!typeOk) {
          var name = (file.name || '').toLowerCase();
          typeOk = /\.(gif|jpe?g|png|webp)$/i.test(name);
        }
        if (!typeOk) {
          alert('Please select a valid image file (jpg, jpeg, png, gif, webp).');
          photoInput.value = '';
          return;
        }
        if (previewImg) {
          try {
            var reader = new FileReader();
            reader.onload = function(evt) {
              previewImg.src = evt.target.result; // data: URL for CSP-friendly preview
            };
            reader.readAsDataURL(file);
          } catch (err) {
            try {
              var url = URL.createObjectURL(file);
              previewImg.src = url;
            } catch (e) {}
          }
        }
      });
    }
  });
})();