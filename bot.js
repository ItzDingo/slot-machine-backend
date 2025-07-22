const { Client, Collection, GatewayIntentBits } = require('discord.js');
const { REST } = require('@discordjs/rest');
const { Routes } = require('discord-api-types/v9');
const mongoose = require('mongoose');
const axios = require('axios');
require('dotenv').config();

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Bot connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const client = new Client({ 
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages
  ] 
});

// Slash Commands Setup
const commands = [
  {
    name: 'balance',
    description: 'Check your current chips and dice balance'
  },
  {
    name: 'daily',
    description: 'Claim your daily reward (1-10 chips)'
  },
  {
    name: 'link',
    description: 'Get the website link to play the slot machine'
  }
];

client.commands = new Collection();

const rest = new REST({ version: '9' }).setToken(process.env.DISCORD_BOT_TOKEN);

client.on('ready', async () => {
  console.log(`Logged in as ${client.user.tag}`);
  
  try {
    console.log('Started refreshing application (/) commands.');
    await rest.put(
      Routes.applicationCommands(process.env.DISCORD_CLIENT_ID),
      { body: commands }
    );
    console.log('Successfully reloaded application (/) commands.');
  } catch (error) {
    console.error(error);
  }
});

client.on('interactionCreate', async interaction => {
  if (!interaction.isCommand()) return;

  const { commandName, user } = interaction;

  if (commandName === 'balance') {
    try {
      const response = await axios.get(`${process.env.BACKEND_URL}/api/user/${user.id}`);
      await interaction.reply(`Your balance: ${response.data.chips} chips and ${response.data.dice} dice`);
    } catch (err) {
      await interaction.reply('Error fetching your balance. Are you logged in on the website?');
    }
  }

  if (commandName === 'daily') {
    try {
      const response = await axios.post(`${process.env.BACKEND_URL}/api/daily/${user.id}`);
      await interaction.reply(`You received ${response.data.reward} chips! New balance: ${response.data.newBalance} chips`);
    } catch (err) {
      if (err.response && err.response.data.error) {
        await interaction.reply(err.response.data.error);
      } else {
        await interaction.reply('Error claiming daily reward. Are you logged in on the website?');
      }
    }
  }

  if (commandName === 'link') {
    await interaction.reply(`Play the slot machine here: ${process.env.FRONTEND_URL}`);
  }
});

// Error handling
client.on('error', error => {
  console.error('Discord client error:', error);
});

process.on('unhandledRejection', error => {
  console.error('Unhandled promise rejection:', error);
});

client.login(process.env.DISCORD_BOT_TOKEN);