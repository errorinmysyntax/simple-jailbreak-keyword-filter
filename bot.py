import os
import discord
import AntiJailBreak as ajb

intents = discord.Intents.default()
intents.message_content = True

client = discord.Client(intents=intents)

@client.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return

    result = ajb.filter_prompt(message.content)
    action = result["action"]

    if action == "BLOCK":
        await message.reply("Sorry, I can't help with that.")
        return

    if action == "RESTRICT":
        await message.reply("I might not be able to follow that request. Try rephrasing.")
        return

    # ALLOW
    await message.reply("Got it! (replace with your real bot logic)")

client.run(os.environ["DISCORD_TOKEN"])
