const jwt = require('jsonwebtoken');

module.exports = async (req, res) => {
  try {
    const expectedSecret = process.env.INTERNAL_API_SECRET;
    const providedSecret = req.headers['x-internal-secret'];

    if (!expectedSecret || providedSecret !== expectedSecret) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const integrationKey = process.env.DOCUSIGN_INTEGRATION_KEY;
    const userId = process.env.DOCUSIGN_USER_ID;
    const privateKey = (process.env.DOCUSIGN_PRIVATE_KEY || '').replace(/\\n/g, '\n');
    const authServer = process.env.DOCUSIGN_AUTH_SERVER || 'account-d.docusign.com';

    if (!integrationKey || !userId || !privateKey) {
      return res.status(500).json({
        error: 'Missing required environment variables'
      });
    }

    const now = Math.floor(Date.now() / 1000);

    const payload = {
      iss: integrationKey,
      sub: userId,
      aud: authServer,
      iat: now,
      exp: now + 3600,
      scope: 'signature impersonation'
    };

    const assertion = jwt.sign(payload, privateKey, {
      algorithm: 'RS256'
    });

    const tokenResponse = await fetch(`https://${authServer}/oauth/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion
      })
    });

    const data = await tokenResponse.json();

    if (!tokenResponse.ok) {
      return res.status(tokenResponse.status).json({
        error: 'DocuSign token request failed',
        details: data
      });
    }

    return res.status(200).json(data);
  } catch (error) {
    return res.status(500).json({
      error: 'Unexpected error',
      details: error.message
    });
  }
};
