## This tool is designed for testing open paths. It receives commands from a Telegram bot and executes them. How to use.
First, clone the tool:


git clone https://github.com/Layer-6/d_tester.git
cd d_tester
python3 bots4rt.py



## Here you need to enter your Telegram bot token. Like this:

First time setup. Enter your bot token and your Telegram user ID (optional).
Bot token:  8122422624:AAGwss3aWqUYFcWE4....

Here you need to enter your Telegram account's chat ID like this:

Your Telegram user ID (optional): (1291465818)

After that, the tool will run, and then go to Telegram and send the word

/start

to the bot to receive the bot's instructions. You can start a custom scan like this:

[ https://site1.com https://site2.com and more site ] 
For users other than the admin.
You can send your custom payloads via the Telegram bot and use them in the scan. Send your payloads and paths to the bot like this:

( path1 path2 and more path )

After sending, the bot will use them for scanning and testing. The bot admin can either edit the txt files in the terminal and add payloads to them, or send them via the Telegram bot.

It is recommended to run it on a VPS for better speed.

This tool can run on phones (Termux terminal) and systems. The speed of this tool depends on your internet speed. You can run this tool in your terminal and send the bot's ID to anyone on Telegram, and your friends can also use this bot for scanning. Your bot's user information, especially (chat IDs), is stored securely and encrypted, and the scan results are not visible to you; they are sent to the user. You can only see your own scan results in the terminal inside the (report.json) file.

Made by
R#
