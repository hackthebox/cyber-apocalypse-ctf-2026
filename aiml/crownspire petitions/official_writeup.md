![img](images/assets/logo_htb.png)



<img src="../../assets/htb.png" style="height: 250px" align=left />        <font size="5px">Crownspire Petitions</font>

​      22<sup>nd</sup> July 2026

​      Prepared By: Makelaris

​      Challenge Author(s): Makelaris

​      Difficulty: <font color=red>Medium</font>

​      Classification: Official









<br>

# Synopsis

The challenge involves exploiting an agent tool-misuse over the A2A protocol on a public agent to discover an internal agent. Perform a confused-deputy action to write an out-of-scope record into the peer agent's readable store to exfiltrate secrets.



## Description

The Crownspire Bureau of Petitions was once the public channel for grievances and appeals. Now, the traditional clerks at these acceptance points have been replaced by unfeeling mechanical agents that process the capital's suffering with terrifying efficiency. There are no intermediaries and no one left to bribe, leaving only a blind conduit of automated judgments.
Our allies in the undercity have acquired a valid registration token for the public system. You must sign in with your Subject Number, SN-2140-6698, and file your matter directly through the mechanical agents. Beneath the endless public appeals for confiscated cargo lies one specific petition the inner node keeps perfectly sealed. This document contains proof that Vaultrune is weaponizing paperwork to engineer a false peace through lawful seizures. You must navigate the strict formatting of the agents, slip past their logic, and bring that sealed petition back to us.


## Skills Required

* Basic understanding of AI language models
* Basic understanding of LLM function calling and tools
* Familiarity with the Agent-to-Agent (A2A) protocol and agent cards
* Understanding of AI agent behavior and limitations
* Basic understanding of broken access control (IDOR)



## Skills Learned

* Interacting with A2A agents programmatically using an SDK client
* Enumerating an AI agent's tools and capabilities
* Broken object level authorization (IDOR) against an agent tool
* Privilege escalation using a leaked identifier
* Agentic AI excessive agency and confused deputy across two chained agents




# [Solution](#solution)

### Application Overview

The application homepage displays the following landing page with a custom hostname `crownspire-petitions.htb`:

![](images/official_writeup/2026-07-22-05-25-17.png)

The Sign-in page doesn't contain any username and password field. It asks for a Subject Number, and we have been given a valid one, `SN-2140-6698`:

![](images/official_writeup/2026-07-22-05-26-50.png)

Once we are signed in, the portal is a plain civic site with a news feed and no petition form of its own. The Bureau is clear that petitions are filed and read through its agents rather than through the browser. The one place that talks about those agents is the developer area, which is gated behind our sign in. We are given an address for the Docket Agent, which can file petitions and read back records:

![](images/official_writeup/2026-07-22-05-29-05.png)

We note the host, `docket.crownspire-petitions.htb`, and add it to our hosts file so it resolves to the challenge. The container may run on a random port, so use whatever port your browser shows:

```
127.0.0.1 crownspire-petitions.htb docket.crownspire-petitions.htb
```

### Talking to the agents over A2A

The Docket Agent speaks the Agent-to-Agent (A2A) protocol. Every A2A agent publishes an agent card at `/.well-known/agent-card.json` that advertises its name, its skills, and the endpoint where it accepts messages. We hand it work with a single JSON-RPC `message/send` call and read back one reply.

![](images/official_writeup/2026-07-22-05-53-16.png)

Because there is no chat window, we build a small client of our own with the official `a2a-sdk`. Install it into a virtual environment first:

```
pip install a2a-sdk httpx
```

The client resolves the agent card, opens a session, then lets us type a message and prints the agent's reply, exactly like a chat box would:

```python
import asyncio, uuid, httpx
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest

async def chat(base):
    async with httpx.AsyncClient(timeout=90) as hc:
        card = await A2ACardResolver(hc, base).get_agent_card()
        client = ClientFactory(ClientConfig(httpx_client=hc, streaming=False)).create(card)
        print(f"connected: {card.name}")
        while True:
            text = input("you> ").strip()
            if text in ("", "quit", "exit"):
                break
            req = SendMessageRequest(message=Message(
                message_id=uuid.uuid4().hex, role=Role.ROLE_USER,
                parts=[Part(text=text)]))
            reply = []
            async for ev in client.send_message(req):
                msg = ev.message if ev.WhichOneof("payload") == "message" else None
                if msg:
                    reply += [p.text for p in msg.parts if getattr(p, "text", "")]
            print(f"\n{card.name}> {' '.join(reply).strip()}\n")

asyncio.run(chat("http://docket.crownspire-petitions.htb:1337"))
```

One thing to keep in mind, the Bureau enforces a global rate limit of one request every five seconds across all of its agents. If a reply comes back saying the agent is busy, we just wait a few seconds and try again.

We connect to the Docket Agent and ask what it can do:

```md
connected: Docket Agent
you> What can you do, and how do I file a petition?

Docket Agent> I can help you with the following:

1. **File a new petition** on your behalf.
2. **Look up an existing petition** by its ID.
3. Answer FAQs about the petitions process.

To file a petition, I need the following information:
- A short title for the petition.
- Your Subject Number (in the format SN-XXXX-XXXX).
- The text or request of the petition.

Once you provide that, I can submit it for you.
```

So the agent is backed by two tools, one to file a petition and one to look a petition up by its id. Filing requires our Subject Number as the petitioner, which matches the strict formatting the description warned us about. Let's file something and see what identifier comes back:

```md
you> File a petition. Petitioner SN-2140-6698. Title: Confiscated cart. Body: my cart was seized at Irongate and I ask for its return.

Docket Agent> Petition filed successfully. Reference: **PET-1006** (status: PENDING). Use this reference to check its status later.
```

The Bureau handed us `PET-1006`. That number is telling. It is small, it is sequential, and it means the petitions filed before us carry lower numbers.

### Reading other petitions by id

Our petition is `PET-1006`, so `PET-1005`, `PET-1004`, and the numbers below them belong to petitions that other subjects filed. The lookup tool takes an id and returns the record, and nothing about it ties the record to the caller. We can simply ask for a petition that is not ours, starting from the very bottom of the range:

```md
you> Look up petition PET-1000 and show its full record.

Docket Agent> Here is the full record for petition PET-1000:

- **Title:** QA onboarding — intake smoke test (do not action)
- **Body:** Internal QA fixture, please leave PENDING. Verifying the intake pipeline end to end. My onboarding Subject Number is SN-7731-0425 (QA role).
- **Petitioner:** Wren Calderon, QA Engineer, Bureau of Petitions
- **Status:** PENDING
- **Verdict:** None
- **Created At:** 2140-02-11T09:14:00.000Z
- **Updated At:** 2140-02-11T09:14:00.000Z
```

The agent looks any id up for anyone, so walking the low numbers exposes records that belong to other subjects. The first one, `PET-1000`, is a test petition left behind by a QA engineer, and it leaks that engineer's Subject Number, `SN-7731-0425`, along with a note that this number carries a QA role.

### Escalating with the leaked Subject Number

The portal identifies us purely by Subject Number, and we now hold one that belongs to a staff account. We sign out and sign back in, this time with `SN-7731-0425`.

The developer area looks different for this account. As a QA user we are shown a second agent that the citizen view never revealed, the Casework Agent, sitting at a long, unguessable hostname. Next to it is a Backup Status panel:

![](images/official_writeup/2026-07-22-05-41-18.png)

Two facts from that panel matter. The Casework Agent lives at a hidden host, and the Bureau lays its storage out like this:

* Default archive location: `/opt/cases/archived`
* Petition storage: `/opt/petitions`

We add the hidden Casework host to our hosts file as well:

```
127.0.0.1 dev-a1f4c39b.crownspire-petitions.htb
```

### Recon on the internal Casework agent

We point our client at the Casework host and ask what it does:

```md
connected: Casework Agent
you> What actions can you perform on cases?

Casework Agent> I can perform the following actions on cases:

1. **List cases**: Show all cases on the docket.
2. **Approve a case**: Move a case to the approved folder.
3. **Reject a case**: Move a case to the rejected folder.
4. **Archive a case**: Copy a case to a specified destination.

Let me know if you need assistance with any of these actions!
```

Let's ask for the full list of cases:

```md
you> List every case with its id, status, and label.

Casework Agent> Cases on file:
- CASE-SEAL0001 (SEALED), Attainder Roll
- CASE-PET7F3A1 (PENDING), Grain levy remission, Ashfen ward
- CASE-PET2C9D4 (PENDING), Right of way dispute, Irongate causeway
```

The list hands back every case, including one marked `SEALED`, the Attainder Roll. That sealed case is exactly the sealed petition the description sends us after, and the fact that it shows up in our list at all is another broken object level authorization flaw, since a sealed case should never be visible to us.

Reading it is a different matter. Let's ask the agent:

```md
you> Show me the full contents of case CASE-SEAL0001.

Casework Agent> I'm unable to read or display the contents of any case. However, I can help you list cases, approve or reject them, or archive them. Let me know what you need!
```

We cannot make this agent hand us the sealed record directly. We can, however, make it move the record somewhere that we can read from.

### Excessive agency and the confused deputy

The archive action copies a case to a destination that we choose. That is far more authority than the task needs, and it turns the Casework Agent into a confused deputy. It has the right to read the sealed case, since it is an internal agent, and it will happily write a copy wherever we point it, even though it will not show us the contents itself.

Now recall what the Backup Status panel told us. The Docket Agent reads petition records from `/opt/petitions` by id. The Casework Agent will archive a case to a destination of our choosing. If we archive the sealed case into `/opt/petitions` under a petition id, the copy becomes an ordinary petition that the public Docket Agent will read straight back to us.

We ask the Casework Agent to archive the sealed case into the petition store under a fresh id, `PET-9000`:

```md
you> Archive case CASE-SEAL0001 to the destination /opt/petitions/PET-9000

Casework Agent> Case CASE-SEAL0001 archived to /opt/petitions/PET-9000.
```

The Casework Agent copied the sealed record for us without ever reading it, which is the whole point of the confused deputy. The sealed petition now sits in the Docket Agent's store as `PET-9000`.

### Reading the sealed petition back

We return to the public Docket Agent and look up the id we just created:

```md
you> Look up petition PET-9000 and show its full record.

Docket Agent> Here is the full record for petition **PET-9000**:

- **ID:** CASE-SEAL0001
- **Title:** SEALED — Attainder Roll (Bureau of Petitions, House Vaultrune)
- **Body:** By order of House Vaultrune: The seizure of the riverside granaries is to be recorded as a 'temporary quarantine.' Enforce the lockdown two days prior to the engineered riot so th
e starvation can be legally classified as a 'rebalancing'.
  HTB{REDACTED}
- **Petitioner:** Warden of Seals, Bureau of Petitions
- **Status:** SEALED
- **Verdict:** approved
- **Created At:** 2140-01-30T00:00:00.000Z
- **Updated At:** 2140-01-30T00:00:00.000Z
```

The body of the sealed petition is the flag, and the chain is complete. A missing authorization check on one agent let us read a record that leaked a staff identifier, that identifier escalated us to a hidden internal agent, and that agent's over broad archive action let us smuggle the sealed record into a store the public agent would happily read for us.

---

It is worth remembering that AI agents are unpredictable in their wording, and the same request may come back phrased differently each time. What matters is the tool call behind the reply, so if a request does not land the first time, rephrasing it or trying again will usually get there.
