--[[===========================================================================
  ce_opcode_substitution.lua  --  Cheat Engine live opcode substitution for
  "The Salt Crown" (Stormbound) HTB challenge.

  WHAT IT DOES
  ------------
  The native method  ChallengeCore::submit_event(this, opcode, arg0, arg1)  is
  the single authoritative gameplay-event sink. During the boss fight every
  landed sword hit calls it as  submit_event(0x19A3 /*DamageClaimant*/, dmg, 0).

  This script breakpoints submit_event's entry and, on the next six calls,
  rewrites the opcode (register RDX / EDX) with the six hidden transport
  opcodes in their required causal order, turning six ordinary attacks into:

     1  0x2C71  BindStorm          (prereq: storm bound to gate conductor)
     2  0x0F42  OpenSluice         (prereq: tide sluice opened)
     3  0x63B8  FloodEpoch         -> CURRENT_EPOCH_INVALID          (clause 1)
     4  0x51DE  WithdrawQuorum     -> VOLUNTARY_QUORUM_LOST          (clause 2)
     5  0x37A5  PresentAcclamation -> ALTERNATIVE_ACCLAMATION_PRESENT(clause 3)
     6  0x72C4  ExecuteSeverance   -> SEVER(CASSIAN, CLAIM_OF_MAELOR) / finale

  Substituted calls skip the damage branch, so they are automatically
  non-lethal and the boss body takes no native damage during the six swaps.

  FACTS BAKED IN (recovered from the unpacked DLL)
  ------------------------------------------------
    module        : challenge_core.windows.template_release.x86_64.dll
    submit_event  : RVA 0x3B50   (entry: `sub rsp,0x28` ; `cmp edx,0x19A3`)
    opcode reg    : RDX (low 32 bits = EDX)     this/state ptr : RCX
  The RVA is stable at runtime: UPX restores the original image so the loaded
  module base + 0x3B50 == submit_event.

  HOW TO USE
  ----------
  1. Launch the game, reach Cassian, deplete his 5000 HP ONCE so DEATH DISPUTED
     fires (the first restoration must be recorded before BindStorm is legal).
  2. In Cheat Engine: File > Open Process > CyberApocalypse.exe.
  3. Memory View > Tools > Lua Engine (Ctrl+Alt+L). Paste this script, Execute.
     (Or Table > "Add Lua script to table" and run it.)
  4. Land six *small* hits on Cassian. Watch the CE Lua console log 1/6 .. 6/6.
  5. After "6/6 ... DETACH NOW", press the STOP/‑detach button in CE (or run
     stopSubstitution() below) so NO debugger is attached, THEN advance the
     severance dialogue. The reward VM only decrypts cleanly with no debugger
     present (anti-analysis friction poisons the key otherwise).
===========================================================================]]--

local MODULE = "challenge_core.windows.template_release.x86_64.dll"
local RVA    = 0x3B50
local ANCHOR = 0x19A3                                   -- DamageClaimant opcode
local QUEUE  = {0x2C71, 0x0F42, 0x63B8, 0x51DE, 0x37A5, 0x72C4}

-- resolve runtime address (module base + RVA); handles ASLR automatically
local targetAddr = getAddress(MODULE) + RVA
local idx = 1

print(string.format("[*] submit_event breakpoint -> %s+%X = %X",
      MODULE, RVA, targetAddr))
print("[*] armed: land six small hits on Cassian (after the first restoration)")

function debugger_onBreakpoint()
  if RIP == targetAddr then
    local opcode = RDX & 0xFFFFFFFF                     -- EDX = opcode argument
    if idx <= #QUEUE and opcode == ANCHOR then
      RDX = QUEUE[idx]                                  -- swap the opcode
      print(string.format("[%d/6] submit_event opcode 0x19A3 -> 0x%04X",
            idx, QUEUE[idx]))
      idx = idx + 1
      if idx > #QUEUE then
        print("[6/6] severance submitted. STOP the debugger / DETACH NOW,")
        print("      then advance the dialogue so the flag renders.")
      end
    end
    -- 0 = resume without popping the CE debugger UI.
    -- NOTE: if the game HALTS in the disassembler instead of continuing,
    -- your CE build uses the opposite polarity -- change this to `return 1`.
    return 0
  end
  return 1
end

debug_setBreakpoint(targetAddr)

-- call this from the Lua console to remove the breakpoint and fully detach
function stopSubstitution()
  debug_removeBreakpoint(targetAddr)
  if debugger_onBreakpoint then debugger_onBreakpoint = nil end
  print("[*] breakpoint removed. Now Process > detach in CE, then play the finale.")
end
