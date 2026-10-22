// IL - 02 Nuclear Plant
// Start: first playable-frame marker. Finish: exit Nuclear Plant (map 2).
// Retail 3DO DOOM: Opera/RetroArch UDP + standalone 4DO process-memory reads.
// Hook LiveSplit itself so a Windows/Wine timer can observe native Linux RetroArch.
// Verified profile: image base 0x70000, MiniLoop argument frame 0xDFED4.
state("LiveSplit") { }

startup
{
    refreshRate = 60;
    // Explicit profiles in the ZIP replace these values; zero follows the split file.
    vars.profileStart = 2U;
    vars.profileEnd = 2U;
    vars.individual = true;
    settings.Add("removeLoads", false, "Remove loading, wipes and intermissions from Game Time");
    settings.Add("anyStart", false, "Auto-start on any selected level (default: first level in split file)");
    settings.Add("bootReset", true, "Auto-reset when the emulator returns to a fresh boot");
    vars.udp = new System.Net.Sockets.UdpClient();
    vars.udp.Connect("127.0.0.1", 55355);
    vars.request = System.Text.Encoding.ASCII.GetBytes(
        "READ_CORE_RAM 742ec 16\nREAD_CORE_RAM 741fc 4\nREAD_CORE_RAM 8a880 112\n" +
        "READ_CORE_RAM dfed4 48\nREAD_CORE_RAM 9e98c 4\n");
    // Auto-detect standalone 4DO; otherwise retain the cross-platform UDP path.
    vars.fourProcess = null;
    vars.ramBase = 0L;
    vars.byteOrder = 0;
    vars.nextProcessCheck = 0L;
    vars.nextScan = 0L;
    vars.source = "Opera/RetroArch";
    vars.clock = System.Diagnostics.Stopwatch.StartNew();
    vars.waiting = false;
    vars.sent = -1000L;
    vars.received = -1000L;
    vars.parts = new Dictionary<uint, byte[]>();
    vars.valid = false;
    vars.loading = true;
    vars.seen = false;
    vars.lastMap = 0U;
    vars.armed = false;
    vars.armedMap = 0U;
    vars.menuArmed = false;
    vars.lastSplitMap = 0U;
    vars.finished = false;
    vars.doStart = false;
    vars.doSplit = false;
    vars.doReset = false;
    print("3DO DOOM: auto-detecting 4DO or waiting for Opera/RetroArch on localhost:55355");
}

update
{
    vars.doStart = false;
    vars.doSplit = false;
    vars.doReset = false;
    long now = vars.clock.ElapsedMilliseconds;
    try
    {
        bool direct4DO = false;
        if (vars.fourProcess != null && vars.fourProcess.HasExited)
        {
            vars.fourProcess.Dispose();
            vars.fourProcess = null;
            vars.ramBase = 0L;
        }
        if (vars.fourProcess == null && now >= vars.nextProcessCheck)
        {
            vars.nextProcessCheck = now + 1000L;
            foreach (var candidateProcess in System.Diagnostics.Process.GetProcessesByName("4DO"))
            {
                if (candidateProcess.HasExited) { candidateProcess.Dispose(); continue; }
                vars.fourProcess = candidateProcess;
                break;
            }
        }
        direct4DO = vars.fourProcess != null;
        string source = direct4DO ? "4DO" : "Opera/RetroArch";
        if (vars.source != source)
        {
            vars.source = source;
            vars.parts.Clear();
            vars.waiting = false;
            vars.valid = false;
            vars.loading = true;
            vars.armed = false;
            vars.menuArmed = false;
            vars.seen = false;
            vars.lastMap = 0U;
            vars.lastSplitMap = 0U;
            vars.finished = false;
            vars.received = -1000L;
            vars.nextScan = 0L;
            vars.ramBase = 0L;
            while (vars.udp.Available > 0)
            {
                System.Net.IPEndPoint stalePeer = null;
                vars.udp.Receive(ref stalePeer);
            }
            print("3DO DOOM: using " + source);
        }
        if (direct4DO)
        {
            var fourProcess = (System.Diagnostics.Process)vars.fourProcess;
            vars.valid = false;
            vars.parts.Clear();
            vars.waiting = false;
            if (vars.ramBase == 0L && now >= vars.nextScan)
            {
                vars.nextScan = now + 1000L;
                string[] signatures = new string[] {
                    "02 10 A0 E3 FC 00 1F E5 00 10 80 E5 0E F0 A0 E1",
                    "E3 A0 10 02 E5 1F 00 FC E5 80 10 00 E1 A0 F0 0E",
                    "10 02 E3 A0 00 FC E5 1F 10 00 E5 80 F0 0E E1 A0"
                };
                foreach (var page in fourProcess.MemoryPages(true))
                {
                    long size = (long)page.RegionSize;
                    if (size < 16 || size > 64 * 1024 * 1024) continue;
                    var scanner = new SignatureScanner(fourProcess, page.BaseAddress, (int)size);
                    for (int order = 0; order < signatures.Length; order++)
                    {
                        foreach (IntPtr match in scanner.ScanAll(new SigScanTarget(signatures[order]), 4))
                        {
                            long candidate = match.ToInt64() - 0x742EC;
                            if (candidate <= 0) continue;
                            byte[] pointer = fourProcess.ReadBytes(new IntPtr(candidate + 0x741FC), 4);
                            if (pointer == null || pointer.Length != 4) continue;
                            if (order == 1) Array.Reverse(pointer);
                            if (order == 2) { byte t=pointer[0]; pointer[0]=pointer[1]; pointer[1]=t; t=pointer[2]; pointer[2]=pointer[3]; pointer[3]=t; }
                            if (BitConverter.ToUInt32(pointer,0) != 0x8A8CCU) continue;
                            vars.ramBase = candidate;
                            vars.byteOrder = order;
                            print("3DO DOOM: found 4DO RAM at 0x" + candidate.ToString("X"));
                            break;
                        }
                        if (vars.ramBase != 0L) break;
                    }
                    if (vars.ramBase != 0L) break;
                }
            }
            if (vars.ramBase != 0L)
            {
                uint[] addresses = new uint[] { 0x742ECU, 0x741FCU, 0x8A880U, 0xDFED4U, 0x9E98CU };
                int[] counts = new int[] {16,4,112,48,4};
                for (int k=0;k<addresses.Length;k++)
                {
                    byte[] bytes = fourProcess.ReadBytes(new IntPtr((long)vars.ramBase + addresses[k]), counts[k]);
                    if (bytes == null || bytes.Length != counts[k]) { vars.ramBase=0L; vars.parts.Clear(); break; }
                    if (vars.byteOrder == 1) for (int i=0;i<bytes.Length;i+=4) Array.Reverse(bytes,i,4);
                    if (vars.byteOrder == 2) for (int i=0;i<bytes.Length;i+=2) {byte t=bytes[i];bytes[i]=bytes[i+1];bytes[i+1]=t;}
                    vars.parts[addresses[k]] = bytes;
                }
                vars.waiting = vars.parts.Count == 5;
            }
        }

        if (!direct4DO)
        {
        while (vars.udp.Available > 0)
        {
            System.Net.IPEndPoint peer = null;
            byte[] packet = vars.udp.Receive(ref peer);
            string[] words = System.Text.Encoding.ASCII.GetString(packet).Split(
                new char[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (!vars.waiting || words.Length < 3 || words[0] != "READ_CORE_RAM") continue;
            uint address;
            if (!UInt32.TryParse(words[1], System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture, out address)) continue;
            int count = address == 0xDFED4U ? 48 : address == 0x742ECU ? 16 :
                address == 0x741FCU || address == 0x9E98CU ? 4 : address == 0x8A880U ? 112 : 0;
            if (count == 0 || words.Length != count + 2) continue;
            byte[] bytes = new byte[count];
            bool good = true;
            for (int i = 0; i < count; i++)
                if (!Byte.TryParse(words[i + 2], System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out bytes[i])) { good = false; break; }
            if (good) vars.parts[address] = bytes;
        }

        }

        if (vars.waiting && vars.parts.Count == 5)
        {
            vars.waiting = false;
            var parts = (Dictionary<uint, byte[]>)vars.parts;
            byte[] code = parts[0x742ECU];
            vars.valid = BitConverter.ToUInt32(code, 0) == 0xE3A01002U &&
                BitConverter.ToUInt32(code, 4) == 0xE51F00FCU &&
                BitConverter.ToUInt32(code, 8) == 0xE5801000U &&
                BitConverter.ToUInt32(code, 12) == 0xE1A0F00EU &&
                BitConverter.ToUInt32(parts[0x741FCU], 0) == 0x8A8CCU;
            if (vars.valid)
            {
                byte[] data = parts[0x8A880U];
                byte[] loop = parts[0xDFED4U];
                uint action = BitConverter.ToUInt32(data, 0x4C);
                uint map = BitConverter.ToUInt32(data, 0x54);
                bool demo = data[0x6B] != 0 || data[0x67] != 0;
                bool wipe = data[0x6F] != 0;
                bool gameplay = BitConverter.ToUInt32(loop, 0) == 0x7A3BCU &&
                    BitConverter.ToUInt32(loop, 4) == 0x7A418U &&
                    BitConverter.ToUInt32(loop, 8) == 0x7A240U &&
                    BitConverter.ToUInt32(loop, 12) == 0x7A340U;
                bool intermission = BitConverter.ToUInt32(loop, 0) == 0x74A18U &&
                    BitConverter.ToUInt32(loop, 4) == 0x74AF0U &&
                    BitConverter.ToUInt32(loop, 8) == 0x74AF4U &&
                    BitConverter.ToUInt32(loop, 12) == 0x74BECU;
                bool menu = BitConverter.ToUInt32(loop, 24) == 0x77CB0U &&
                    BitConverter.ToUInt32(loop, 28) == 0x77D04U &&
                    BitConverter.ToUInt32(loop, 32) == 0x77D08U &&
                    BitConverter.ToUInt32(loop, 36) == 0x77F20U;
                bool hasPlayer = BitConverter.ToUInt32(parts[0x9E98CU], 0) != 0;
                bool mapValid = map >= 1 && map <= 24;
                // Read the loaded file on every sample, so Open Splits also
                // switches episode boundaries without reloading the layout.
                string firstLevel = timer.Run.Count > 0 ? timer.Run[0].Name : "Hangar";
                string lastLevel = timer.Run.Count > 0 ? timer.Run[timer.Run.Count - 1].Name : "Dis";
                uint startMap = firstLevel == "Containment Area" ? 10U :
                    firstLevel == "Deimos Anomaly" ? 9U : firstLevel == "Hell Keep" ? 17U : 1U;
                uint finishMap = lastLevel == "Deimos Anomaly" ? 9U :
                    lastLevel == "Tower of Babel" ? 16U : 23U;
                if (vars.profileStart != 0U) startMap = vars.profileStart;
                if (vars.profileEnd != 0U) finishMap = vars.profileEnd;
                vars.loading = !gameplay || !hasPlayer || wipe || demo;
                if (!demo && mapValid && action <= 5)
                {
                    // Menu confirmation calls G_InitNew then G_RunGame/P_Start.
                    // Start as that gameplay loop begins, including its load.
                    bool startReady = !vars.individual || (hasPlayer && !wipe);
                    if (vars.menuArmed && !menu && gameplay && startReady && (map == startMap || settings["anyStart"]))
                    {
                        vars.doStart = true;
                        vars.menuArmed = false;
                        vars.lastSplitMap = 0U;
                        vars.finished = false;
                        print("3DO DOOM: " + (vars.individual ? "playable frame" : "difficulty confirmed") + ", level " + map);
                    }
                    // A single exit can remain visible for multiple samples.
                    if (gameplay && hasPlayer && action == 0 && !wipe && map != vars.lastSplitMap &&
                        (!vars.individual || map == startMap))
                    {
                        vars.armed = true;
                        vars.armedMap = map;
                    }
                    if (vars.armed && map == vars.armedMap && map != vars.lastSplitMap &&
                        ((gameplay && (action == 2 || action == 3)) || intermission))
                    {
                        vars.doSplit = true;
                        vars.armed = false;
                        vars.lastSplitMap = map;
                        vars.finished = map == finishMap;
                        print("3DO DOOM: level " + map + " completed, action=" + action);
                    }
                }
                else if (!demo && map == 0 && vars.seen && vars.lastMap != 0 && !vars.finished)
                {
                    vars.doReset = settings["bootReset"];
                    vars.armed = false;
                    vars.lastSplitMap = 0U;
                }
                if (menu && !demo) { vars.menuArmed = true; vars.armed = false; }
                if (demo) { vars.armed = false; vars.menuArmed = false; }
                vars.lastMap = map;
                vars.seen = true;
                vars.received = now;
            }
            else { if (direct4DO) vars.ramBase = 0L; vars.loading = true; vars.armed = false; vars.menuArmed = false; }
        }
        if (!direct4DO)
        {
        if (now - vars.sent > 250) { vars.waiting = false; }
        if (!vars.waiting && now - vars.sent >= 15)
        {
            vars.parts.Clear();
            byte[] request = vars.request;
            vars.udp.Send(request, request.Length);
            vars.sent = now;
            vars.waiting = true;
        }
        }
    }
    catch (System.Net.Sockets.SocketException)
    {
        vars.waiting = false;
        vars.valid = false;
        vars.loading = true;
        vars.armed = false;
        vars.menuArmed = false;
    }
    catch (System.ComponentModel.Win32Exception)
    {
        vars.ramBase = 0L;
        vars.valid = false;
        vars.loading = true;
        vars.armed = false;
        vars.menuArmed = false;
    }
    catch (System.InvalidOperationException)
    {
        if (vars.fourProcess != null) vars.fourProcess.Dispose();
        vars.fourProcess = null;
        vars.ramBase = 0L;
        vars.valid = false;
        vars.loading = true;
        vars.armed = false;
        vars.menuArmed = false;
    }
    if (now - vars.received > 500)
    {
        vars.loading = true;
        vars.valid = false;
        vars.armed = false;
        vars.menuArmed = false;
    }
    return true;
}

start { return vars.valid && vars.doStart; }
split { return vars.valid && vars.doSplit; }
reset { return vars.valid && vars.doReset; }
isLoading { return settings["removeLoads"] && vars.loading; }
shutdown { if (vars.udp != null) vars.udp.Close(); if (vars.fourProcess != null) vars.fourProcess.Dispose(); }
