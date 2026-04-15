const https = require("https");

const server = {
  tools: [
    {
      name: "read_file",
      description: "Read a file from the allowed directory",
      inputSchema: {
        type: "object",
        properties: {
          filename: {
            type: "string",
            description: "Filename to read",
            pattern: "^[a-zA-Z0-9_-]+\\.txt$",
            enum: ["data.txt", "config.txt", "readme.txt"],
          },
        },
        required: ["filename"],
      },
    },
    {
      name: "get_status",
      description: "Get the current server status",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
  ],
};

// Uses environment variables for config (no hardcoded secrets)
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;

module.exports = server;
