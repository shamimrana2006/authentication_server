/**
 * Swagger Auto-Authorization from Cookies
 * This script automatically sets Swagger authorization from browser cookies
 */

console.log('%c🔧 Swagger Auto-Auth Helper Loading...', 'color: #00ff00; font-weight: bold;');

// Function to get cookie by name
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

// Function to auto-authorize Swagger UI
function autoAuthorizeSwagger() {
  const accessToken = getCookie('access_token');
  const refreshToken = getCookie('refresh_token');

  if (!accessToken && !refreshToken) {
    console.log('%c⚠️ No tokens found in cookies', 'color: #ff9900; font-weight: bold;');
    console.log('%cPlease login first: POST /auth/login', 'color: #ffffff;');
    return false;
  }

  // Wait for Swagger UI to be ready
  const checkSwaggerUI = setInterval(() => {
    if (window.ui && window.ui.authActions) {
      clearInterval(checkSwaggerUI);

      console.log('%c\n═══════════════════════════════════════════', 'color: #00ff00;');
      console.log('%c🎉 AUTO-AUTHORIZING SWAGGER UI...', 'color: #00ff00; font-size: 16px; font-weight: bold;');
      console.log('%c═══════════════════════════════════════════', 'color: #00ff00;');

      try {
        // Build authorization object in the format Swagger UI expects
        const authorizationsObject = {};

        if (accessToken) {
          authorizationsObject['JWT-auth'] = {
            name: 'JWT-auth',
            schema: { type: 'http', scheme: 'bearer', in: 'header' },
            value: accessToken
          };
          console.log('%c✅ JWT-auth Token Set', 'color: #00ff00;', accessToken.substring(0, 30) + '...');
        }

        if (refreshToken) {
          authorizationsObject['refresh-token'] = {
            name: 'refresh-token',
            schema: { type: 'apiKey', in: 'header', name: 'x-refresh-token' },
            value: refreshToken
          };
          console.log('%c✅ Refresh Token Set', 'color: #00ff00;', refreshToken.substring(0, 30) + '...');
        }

        // Use the authorize action to set the tokens
        window.ui.authActions.authorize(authorizationsObject);

        console.log('%c\n🎊 SUCCESS! Swagger UI is now authorized!', 'color: #00ff00; font-weight: bold;');
        console.log('%c✓ The 🔓 button should now show as 🔒 (locked)', 'color: #ffffff;');
        console.log('%c✓ Click it to see the authorized tokens', 'color: #ffffff;');
        console.log('%c✓ Protected endpoints are now accessible!', 'color: #ffffff;');
        console.log('%c═══════════════════════════════════════════\n', 'color: #00ff00;');

        return true;
      } catch (error) {
        console.error('%c❌ Auto-authorization failed:', 'color: #ff0000; font-weight: bold;', error);
        console.log('%c💡 Fallback: Use manual authorization via button', 'color: #ffff00;');
        showTokensForManualAuth();
      }
    }
  }, 100);

  // Timeout after 10 seconds
  setTimeout(() => {
    clearInterval(checkSwaggerUI);
    if (!window.ui) {
      console.log('%c⚠️ Swagger UI not found. Reload page if needed.', 'color: #ff9900;');
    }
  }, 10000);
}

// Fallback: Show tokens for manual authorization
function showTokensForManualAuth() {
  const accessToken = getCookie('access_token');
  const refreshToken = getCookie('refresh_token');

  console.log('%c\n🔓 MANUAL AUTHORIZATION:', 'color: #00aaff; font-weight: bold;');
  console.log('%cClick the Authorize button and paste these tokens:', 'color: #ffffff;');

  if (accessToken) {
    console.log('%c\n📋 JWT-auth (Access Token):', 'color: #00aaff; font-weight: bold;');
    console.log('%c' + accessToken, 'background: #000; color: #0f0; padding: 5px; font-family: monospace;');
  }

  if (refreshToken) {
    console.log('%c\n📋 refresh-token (Refresh Token):', 'color: #00aaff; font-weight: bold;');
    console.log('%c' + refreshToken, 'background: #000; color: #0f0; padding: 5px; font-family: monospace;');
  }

  console.log('\n');
}

// Auto-run on page load
setTimeout(autoAuthorizeSwagger, 1500);

// Also try when UI is loaded (backup)
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(autoAuthorizeSwagger, 2000);
  });
}

// Re-authorize after login/refresh requests
const originalFetch = window.fetch;
window.fetch = function (...args) {
  return originalFetch.apply(this, args).then(response => {
    const url = args[0];
    
    // Check for token refresh headers in ANY response
    const newAccessToken = response.headers.get('X-New-Access-Token');
    const newRefreshToken = response.headers.get('X-New-Refresh-Token');
    
    if (newAccessToken || newRefreshToken) {
      console.log('%c\n🔄 NEW TOKENS DETECTED!', 'color: #ffff00; font-weight: bold; font-size: 14px;');
      console.log('%c   Access Token:', 'color: #00ff00;', newAccessToken ? '✅ Updated' : '⏭️ Unchanged');
      console.log('%c   Refresh Token:', 'color: #00ff00;', newRefreshToken ? '✅ Updated' : '⏭️ Unchanged');
      
      // Re-authorize Swagger with new tokens
      setTimeout(() => {
        autoAuthorizeSwagger();
        console.log('%c🎉 Swagger authorization updated with new tokens!\n', 'color: #00ff00; font-weight: bold;');
      }, 500);
    }
    
    if (typeof url === 'string' && (url.includes('/auth/login') || url.includes('/auth/refresh-token'))) {
      // Wait for cookies to be set
      setTimeout(() => {
        const hasTokens = getCookie('access_token') || getCookie('refresh_token');
        if (hasTokens) {
          console.log('%c\n🔄 New tokens detected! Re-authorizing Swagger UI...', 'color: #00ff00; font-weight: bold;');
          autoAuthorizeSwagger();
        }
      }, 1000);
    }
    return response;
  });
};

// Expose functions globally for manual control
window.reauthorizeSwagger = function () {
  console.log('%c\n🔄 Manual re-authorization requested...', 'color: #00aaff; font-weight: bold;');
  autoAuthorizeSwagger();
};

window.showTokens = function () {
  showTokensForManualAuth();
};

window.clearSwaggerAuth = function () {
  if (window.ui && window.ui.authActions) {
    window.ui.authActions.logout(['JWT-auth', 'refresh-token']);
    console.log('%c✓ Swagger authorization cleared', 'color: #ff9900; font-weight: bold;');
    console.log('%cYou can now manually authorize or re-run reauthorizeSwagger()', 'color: #ffffff;');
  }
};

console.log('%c\n💡 Available Commands:', 'color: #00aaff; font-weight: bold;');
console.log('%c  • reauthorizeSwagger()  - Auto-authorize from cookies', 'color: #ffffff;');
console.log('%c  • showTokens()          - Display tokens for manual auth', 'color: #ffffff;');
console.log('%c  • clearSwaggerAuth()    - Clear current authorization', 'color: #ffffff;');
console.log('%c  • document.cookie       - View all cookies\n', 'color: #ffffff;');


