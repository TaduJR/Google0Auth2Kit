# GoogleOAuth2Kit

## Description

GoogleOAuth2Kit is a Deno library that provides abstractions for simplifying Google API authentication. It handles the entire authentication flow, including generating an authentication URL, retrieving the authorization code, exchanging it for an access token, handling refresh tokens, and managing errors. With GoogleOAuth2Kit, developers can seamlessly authenticate with Google APIs without worrying about the intricacies of the authentication process.

## Features

- Generates authentication URL
- Retrieves authorization code
- Exchanges authorization code for access token
- Handles refresh tokens
- Error handling with detailed diagnostics

## Prerequisites

Before using GoogleOAuth2Kit, ensure you have the following prerequisites installed:

- Deno (version 1.40 or higher)

## Pre-Usage Requirements

- Rename .env.google.example to .env.google
- Fill your **client_id, client_secret** and list of **scopes** obtained from Google

## Usage

```js
import { GoogleOAuth2Kit } from "google-oauth2-kit";

const scopes = [
  "https://www.googleapis.com/auth/youtube.readonly",
  "https://www.googleapis.com/auth/youtube.upload",
];
const envPath = "./.env.google";

const oauth2Client = new Google0Auth2Kit(scopes, envPath);
```
