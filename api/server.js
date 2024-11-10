const express = require('express');
const session = require('express-session');
const cors = require('cors');
const querystring = require('querystring');
const axios = require('axios');
const pool = require('./db');

const { generateRandomString } = require('../utils/utils');
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER, // Use your new no-reply email
    pass: process.env.GMAIL_PASS, // Use your app-specific password
  },
});

const app = express();

// Middleware
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'https://www.moodmuzik.com', // Fallback to hardcoded URL if not set
    credentials: true, // Allow cookies (session) to be included in the requests
  })
);

app.use(express.json());
app.set('trust proxy', 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET, // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: true, // true in production
      maxAge: 60 * 60 * 1000, // Session lasts for 1 hour (in milliseconds)
      sameSite: 'none',
    },
  })
);
// Your existing routes...

const client_id = process.env.SPOTIFY_CLIENT_ID;
const redirect_uri = process.env.REDIRECT_URI;
const client_secret = process.env.SPOTIFY_CLIENT_SECRET;

//LOGIN AUTH
app.get('/login', function (req, res) {
  const state = generateRandomString(16);
  req.session.state = state; // Store the state in session
  const scope =
    'user-read-private user-read-email playlist-modify-public playlist-modify-private user-top-read ugc-image-upload';

  res.redirect(
    'https://accounts.spotify.com/authorize?' +
      querystring.stringify({
        response_type: 'code',
        client_id: client_id,
        scope: scope,
        redirect_uri: redirect_uri,
        state: state,
      })
  );
});

//REDIRECT ONCE AUTH COMPLETE
app.get('/callback', async (req, res) => {
  const code = req.query.code || null;
  const state = req.query.state || null;

  if (!state) {
    return res.redirect(
      '/#' + querystring.stringify({ error: 'state_mismatch' })
    );
  }

  try {
    const tokenResponse = await axios.post(
      'https://accounts.spotify.com/api/token',
      querystring.stringify({
        code: code,
        redirect_uri: redirect_uri,
        grant_type: 'authorization_code',
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization:
            'Basic ' +
            Buffer.from(client_id + ':' + client_secret).toString('base64'),
        },
      }
    );

    const { access_token, refresh_token } = tokenResponse.data;

    // Store tokens in the session
    req.session.access_token = access_token;
    req.session.refresh_token = refresh_token;

    // Make sure to use return to prevent sending multiple responses
    return res.redirect(`${process.env.FRONTEND_URL}/artists`);
  } catch (error) {
    console.error('Error during token exchange:', error);

    // Use return to ensure no further code is executed after sending a response
    return res.redirect(
      '/#' + querystring.stringify({ error: 'invalid_token' })
    );
  }
});

//refresh token route
app.get('/refresh_token', (req, res) => {
  const refresh_token = req.query.refresh_token;

  if (!refresh_token) {
    return res.status(400).send('Refresh token is required');
  }

  axios
    .post(
      'https://accounts.spotify.com/api/token',
      querystring.stringify({
        grant_type: 'refresh_token',
        refresh_token: refresh_token,
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization:
            'Basic ' +
            Buffer.from(client_id + ':' + client_secret).toString('base64'),
        },
      }
    )
    .then((response) => {
      const access_token = response.data.access_token;
      res.json({ access_token: access_token });
    })
    .catch((error) => {
      console.error(
        'Error refreshing token:',
        error.response?.data || error.message
      );
      res.status(500).send('Failed to refresh token');
    });
});

const ensureAuthenticated = (req, res, next) => {
  if (req.session.access_token) {
    return next();
  }
  res.status(401).json({ error: 'Not authenticated' });
};

// sign up
app.post('/signup', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required.' });
  }

  try {
    // Insert user into database
    const response = await pool.query(
      'INSERT INTO "users" (email) VALUES ($1) RETURNING *',
      [email]
    );

    // Send a confirmation email to the user
    const sendConfirmationEmail = async (userEmail) => {
      const mailOptions = {
        from: 'noreply@moodmuzik.com',
        to: userEmail,
        subject: 'Thank you for signing up',
        text: 'Thank you for signing up. You will receive a link to access Mood Muzik shortly.',
      };

      await transporter.sendMail(mailOptions);
    };

    // Send an email to you when a user signs up
    const sendSignupNotification = async (userEmail) => {
      const mailOptions = {
        from: 'noreply@moodmuzik.com',
        to: 'jaquavia@moodmuzik.com',
        subject: 'New User Signup',
        text: `A new user has signed up with the email: ${userEmail}`,
      };

      await transporter.sendMail(mailOptions);
    };

    // Call the email sending functions asynchronously
    sendConfirmationEmail(email).catch(console.error);
    sendSignupNotification(email).catch(console.error);

    res.status(201).json({
      message: 'User registered successfully',
      user: response.rows[0],
    });
  } catch (err) {
    console.error('Database error:', err); // Log detailed error to Render logs

    // Send error details in response for debugging (remove in production)
    res
      .status(500)
      .json({ error: 'Internal server error', details: err.message });
  }
});

//get user info
app.get('/user', ensureAuthenticated, async (req, res) => {
  const accessToken = req.session.access_token; // Retrieve the access token from the session

  if (!accessToken) {
    return res
      .status(401)
      .json({ error: 'No access token found. Please log in.' });
  }

  try {
    const response = await axios.get('https://api.spotify.com/v1/me', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    });

    // Send the user information back to the client
    res.json(response.data);
  } catch (err) {
    console.error('Error fetching user info from Spotify:', err.message);
    res.status(500).json({ error: 'Failed to fetch user information' });
  }
});

// Create playlist
app.post('/create_playlist', ensureAuthenticated, async (req, res) => {
  const { name, description, user_id } = req.body;
  const accessToken = req.session.access_token;

  try {
    const response = await axios.post(
      `https://api.spotify.com/v1/users/${user_id}/playlists`,
      { name, description, public: false }, // Include the necessary fields
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      }
    );

    if (response.status === 201) {
      res.status(201).json(response.data); // Return the data from Spotify
    } else {
      res.status(response.status).json({ error: 'Failed to create playlist' });
    }
  } catch (err) {
    console.error('Error creating playlist:', err.message);
    // Ensure you're returning a JSON error response
    res
      .status(500)
      .json({ error: 'Internal server error', details: err.message });
  }
});

// get playlist
app.get('/get_playlist', ensureAuthenticated, async (req, res) => {
  const { playlist_id } = req.params;
  const accessToken = req.session.access_token;

  try {
    const response = await axios.post(
      `https://api.spotify.com/v1/playlists/${playlist_id}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      }
    );

    if (response.status === 201) {
      res.status(201).json(response.data); // Return the data from Spotify
    } else {
      res.status(response.status).json({ error: 'Failed to get playlist' });
    }
  } catch (err) {
    console.error('Error getting playlist:', err.message);
    // Ensure you're returning a JSON error response
    res
      .status(500)
      .json({ error: 'Internal server error', details: err.message });
  }
});

// Get top artists
app.get('/artists', ensureAuthenticated, async (req, res) => {
  const { type = 'artists', time_range = 'long_term', limit = 50 } = req.query;
  const accessToken = req.session.access_token; // Retrieve access token from session

  if (!accessToken) {
    return res
      .status(401)
      .json({ error: 'No access token found. Please log in.' });
  }

  try {
    const response = await axios.get(
      `https://api.spotify.com/v1/me/top/${type}`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        params: {
          time_range: time_range,
          limit: limit,
        },
      }
    );
    res.json(response.data);
  } catch (error) {
    console.error(
      'Error getting top artists:',
      error.response?.data || error.message
    );
    res.status(error.response?.status || 500).send('Failed to get artists');
  }
});

app.post('/add', ensureAuthenticated, async (req, res) => {
  const { playlist_id, uris } = req.body; // Expect both `playlist_id` and `uris` in the body of the request
  const accessToken = req.session.access_token; // Retrieve access token from session

  // Validate input
  if (!playlist_id || !uris || !Array.isArray(uris) || uris.length === 0) {
    return res.status(400).json({ error: 'Invalid request body' });
  }

  try {
    const response = await axios.post(
      `https://api.spotify.com/v1/playlists/${playlist_id}/tracks`,
      { uris }, // Body containing the array of track URIs to add
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
      }
    );

    // Check for successful response
    if (response.status === 201) {
      return res
        .status(201)
        .json({ message: 'Tracks successfully added to playlist' });
    } else {
      return res
        .status(response.status)
        .json({ message: 'Failed to add tracks', details: response.data });
    }
  } catch (err) {
    console.error('Error adding tracks to playlist:', err.message);
    return res
      .status(500)
      .json({ error: 'Internal server error', details: err.response?.data });
  }
});

// get recommendations
app.get('/tracks', ensureAuthenticated, async (req, res) => {
  const accessToken = req.session.access_token;

  const {
    limit,
    artistsId,
    valence,
    energy,
    danceability,
    acousticness,
    tempo,
  } = req.query;

  // Convert comma-separated strings to arrays and parse numbers
  const valenceRange = valence ? valence.split(',').map(Number) : [];
  const energyRange = energy ? energy.split(',').map(Number) : [];
  const danceabilityRange = danceability
    ? danceability.split(',').map(Number)
    : null;
  const acousticnessRange = acousticness
    ? acousticness.split(',').map(Number)
    : null;
  const tempoRange = tempo ? tempo.split(',').map(Number) : null;

  try {
    const params = new URLSearchParams({
      limit: limit.toString(),
      seed_artists: artistsId,
      min_valence: valenceRange[0]?.toString(),
      max_valence: valenceRange[1]?.toString(),
      min_energy: energyRange[0]?.toString(),
      max_energy: energyRange[1]?.toString(),
    });

    // Add optional parameters if they exist
    if (danceabilityRange) {
      params.append('min_danceability', danceabilityRange[0]?.toString());
      params.append('max_danceability', danceabilityRange[1]?.toString());
    }
    if (acousticnessRange) {
      params.append('min_acousticness', acousticnessRange[0]?.toString());
      params.append('max_acousticness', acousticnessRange[1]?.toString());
    }
    if (tempoRange) {
      params.append('min_tempo', tempoRange[0]?.toString());
      params.append('max_tempo', tempoRange[1]?.toString());
    }

    const response = await fetch(
      `https://api.spotify.com/v1/recommendations?${params.toString()}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch tracks: ${response.statusText}`);
    }

    const data = await response.json();
    res.json({ tracks: data.tracks });
  } catch (error) {
    console.error('Error fetching tracks from Spotify API:', error);
    res.status(500).json({ message: 'Error fetching tracks' });
  }
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

module.exports = app;
