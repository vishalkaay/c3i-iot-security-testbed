import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Cable, CheckCircle2, Power, Zap } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { Card, ErrorBanner, InlineCode, PageHeader, Step, Table } from "../components/ui";

export default function Hardware() {
  const qc = useQueryClient();
  const hw = useQuery({
    queryKey: ["hardware"],
    queryFn: api.hardwareStatus,
  });
  const engagements = useQuery({ queryKey: ["engagements"], queryFn: api.engagements });
  const [engagementId, setEngagementId] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [lastAction, setLastAction] = useState<string>("");

  const runModule = useMutation({
    mutationFn: (v: { action: string; params: Record<string, unknown> }) =>
      api.createJob({
        engagement_id: engagementId || undefined,
        plugin: "hardware",
        action: v.action,
        params: v.params,
      }),
    onSuccess: (job) => {
      setLastAction(`Started ${job.plugin}.${job.action} (job ${job.id.slice(0, 8)})`);
      qc.invalidateQueries({ queryKey: ["recentJobs"] });
    },
    onError: setError,
  });

  const h = hw.data;
  const mock = h?.gpio_is_mock;

  return (
    <div className="mx-auto max-w-[1100px] space-y-6 fade-in">
      <PageHeader
        title="Hardware workbench"
        subtitle="Connect directly over USB or use a Raspberry Pi controller. Inspect UART, SPI, I2C and logic traces, recover flash, and keep the evidence."
      />

      <ErrorBanner error={error || hw.error} />

      {/* rig status banner */}
      <Card
        className={
          mock
            ? "border-amber-800 bg-amber-950/20"
            : "border-emerald-800 bg-emerald-950/20"
        }
      >
        <div className="flex items-start gap-3">
          {mock ? (
            <AlertTriangle className="h-5 w-5 text-amber-400 mt-0.5" />
          ) : (
            <CheckCircle2 className="h-5 w-5 text-emerald-400 mt-0.5" />
          )}
          <div className="flex-1">
            <div className="font-medium text-slate-100">
              {!h ? "Checking hardware capabilities…" : mock ? "GPIO simulation · USB devices can still be used" : "GPIO backend available"}
            </div>
            <div className="text-sm text-slate-400 mt-1">
              {mock ? (
                <>
                  GPIO backend is <InlineCode>mock</InlineCode>. Run the backend on the
                   Raspberry Pi 5 with a compatible GPIO backend to drive power controls.
                   USB–TTL UART adapters and USB SPI programmers work directly from this host.
                </>
              ) : (
                <>GPIO backend: <InlineCode>{h?.gpio_backend}</InlineCode></>
              )}
            </div>
            <div className="mt-2 grid sm:grid-cols-2 lg:grid-cols-5 gap-2 text-xs">
              <div>
                <span className="text-slate-500">UART port:</span>{" "}
                <InlineCode>{h?.uart_port || "none detected"}</InlineCode>
              </div>
              <div>
                <span className="text-slate-500">Serial ports:</span>{" "}
                <InlineCode>{h?.serial_ports?.length || 0}</InlineCode>
              </div>
              <div>
                <span className="text-slate-500">Debug probes:</span>{" "}
                <InlineCode>{h?.debug_probes?.length || 0}</InlineCode>
              </div>
              <div>
                <span className="text-slate-500">Logic analyzer:</span>{" "}
                <span className={h?.logic_analyzer_available ? "text-emerald-400" : "text-slate-400"}>
                  {h?.logic_analyzer_available ? "sigrok ready" : "not installed"}
                </span>
              </div>
              <div>
                <span className="text-slate-500">Ready:</span>{" "}
                <span className={h?.ready_for_physical_tests ? "text-emerald-400" : "text-amber-400"}>
                  {h?.ready_for_physical_tests ? "yes" : "no"}
                </span>
              </div>
            </div>
          </div>
        </div>
      </Card>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card title="Direct USB connection" hint="Laptop / workstation"><div className="space-y-3 text-sm text-slate-400"><div className="terminal p-4 text-accent">Host → USB–TTL adapter → DUT UART</div><p>Cross TX to RX, RX to TX, and connect common ground. Match the adapter's logic voltage to the target. Keep the DUT on its own supply; leave adapter VCC disconnected.</p><p>For flash reads, connect a voltage-compatible CH341A or FT2232 programmer and choose it in the SPI module.</p></div></Card>
        <Card title="Raspberry Pi controller" hint="Remote bench"><div className="space-y-3 text-sm text-slate-400"><div className="terminal p-4 text-accent">Browser → Pi backend → UART / SPI / GPIO</div><p>Run the backend on the Pi, then open its web console from your laptop. Adapters and GPIO hardware attach to the Pi running the backend.</p><p>The serial port is resolved on the backend host, not on the computer displaying the browser.</p></div></Card>
      </div>
      <Card title="Camera filesystem workflow"><div className="grid gap-3 sm:grid-cols-3">{[["uart_console", "1 / Inspect console", "Confirm a usable UART console."], ["serial_exec", "2 / Check shell access", "Use known credentials and inspect the OS."], ["filesystem_dump", "3 / Recover partition", "List partitions, then stream the selected image."]].map(([module, title, description]) => <Link key={module} className="domain-tile" to={`/runner?plugin=hardware&module=${module}`}><h3 className="text-sm">{title}</h3><p className="mt-2 text-xs text-slate-400">{description}</p></Link>)}</div><p className="mt-4 text-xs text-slate-500">UART wiring alone does not grant shell access. A dump needs a readable partition and a working Linux shell. Physical-device validation is still required.</p></Card>

      <Card title="Board-level recon" hint="read-only first">
        <div className="grid gap-3 sm:grid-cols-3">
          {[
            ["spi_identify", "SPI flash identity", "Read JEDEC ID, capacity and write-protection state before any dump."],
            ["i2c_scan", "I2C bus scan", "Find EEPROMs, sensors and debug/control devices; then dump one address."],
            ["logic_capture", "Logic decode", "Capture UART, SPI or I2C passively with sigrok-cli and save the transcript."],
          ].map(([module, title, description]) => (
            <Link key={module} className="domain-tile" to={`/runner?plugin=hardware&module=${module}`}>
              <h3 className="text-sm">{title}</h3>
              <p className="mt-2 text-xs text-slate-400">{description}</p>
            </Link>
          ))}
        </div>
        <p className="mt-4 text-xs text-slate-500">
          A read-only identity/scan is not a vulnerability by itself. Confirm chip voltage,
          common ground and pinout before connecting a probe. Logic capture listens only;
          it never drives the target bus.
        </p>
      </Card>

      {/* connection guide */}
      <Card title="How to connect the device under test">
        <div className="space-y-4">
          <Step n={1} title="Power everything off">
            Never connect or disconnect probes while the DUT is powered.
          </Step>
          <Step n={2} title="Find the UART pads on the DUT">
            Look for 4 pads labelled <InlineCode>TX RX GND VCC</InlineCode> (or a header).
            Confirm 3.3 V logic with a multimeter — the Pi is not 5 V tolerant.
          </Step>
          <Step n={3} title="Wire UART (cross-over)">
            Pi <InlineCode>TX (pin 8)</InlineCode> → DUT <InlineCode>RX</InlineCode>; Pi{" "}
            <InlineCode>RX (pin 10)</InlineCode> → DUT <InlineCode>TX</InlineCode>; a{" "}
            <b>common ground</b> between Pi and DUT is mandatory.
          </Step>
          <Step n={4} title="Wire power control">
            Put the relay/optocoupler in the DUT's power path so the Pi can power-cycle it
            (used for boot-log capture and glitching).
          </Step>
          <Step n={5} title="Check the rig, then run detect_baud">
            Use the quick actions below to confirm the console and find the baud rate.
          </Step>
        </div>
      </Card>

      {/* pin map */}
      <Card title="Pin map" hint="BCM numbering · 3.3 V logic" dense>
        <Table>
          <thead>
            <tr>
              <th>Signal</th>
              <th>BCM</th>
              <th>Physical pin</th>
              <th>Connects to</th>
            </tr>
          </thead>
          <tbody>
            {[
              ["UART TX", h?.pins?.uart_tx_bcm, h?.pins?.uart_tx_pin, "DUT RX"],
              ["UART RX", h?.pins?.uart_rx_bcm, h?.pins?.uart_rx_pin, "DUT TX"],
              ["Relay power", h?.pins?.relay_power_bcm, h?.pins?.relay_power_pin, "relay IN"],
              ["Optocoupler", h?.pins?.optocoupler_power_bcm, h?.pins?.optocoupler_power_pin, "optocoupler IN"],
              ["Glitch channel", h?.pins?.glitch_channel_bcm, h?.pins?.glitch_channel_pin, "channel select"],
              ["Glitch trigger", h?.pins?.glitch_trigger_bcm, h?.pins?.glitch_trigger_pin, "fast pulse"],
              ["SPI MOSI", "10", h?.pins?.spi_mosi_pin, "flash DI (pin 5)"],
              ["SPI MISO", "9", h?.pins?.spi_miso_pin, "flash DO (pin 2)"],
              ["SPI SCLK", "11", h?.pins?.sclk ?? h?.pins?.spi_sclk_pin, "flash CLK (pin 6)"],
              ["SPI /CS", "8", h?.pins?.spi_ce0_pin, "flash /CS (pin 1)"],
            ].map(([sig, bcm, pin, to]) => (
              <tr key={String(sig)}>
                <td className="td">{sig}</td>
                <td className="td font-mono text-xs">{bcm}</td>
                <td className="td font-mono text-xs">{pin}</td>
                <td className="td text-slate-400">{to}</td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>

      {/* quick actions */}
      <Card title="Quick actions" hint={"runs the hardware modules"}>
        <div className="mb-4">
          <label className="label" htmlFor="hardware-engagement">Attach to engagement (required for gated tests)</label>
          <select
            id="hardware-engagement"
            className="input"
            value={engagementId}
            onChange={(e) => setEngagementId(e.target.value)}
          >
            <option value="">— none —</option>
            {engagements.data?.map((e) => (
              <option key={e.id} value={e.id}>
                {e.name} ({e.status})
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            className="btn-ghost"
            disabled={runModule.isPending}
            onClick={() => runModule.mutate({ action: "detect_baud", params: { candidates: [9600, 19200, 38400, 57600, 115200], read_seconds: 2, power_cycles: 0 } })}
          >
            <Cable className="h-4 w-4" /> Detect baud rate
          </button>
          <button
            className="btn-ghost"
            disabled={runModule.isPending}
            onClick={() => runModule.mutate({ action: "capture_bootlog", params: { baud: 115200, read_seconds: 15, power_cycle: true } })}
          >
            Capture boot log
          </button>
          <button
            className="btn-ghost"
            disabled={runModule.isPending}
            onClick={() => runModule.mutate({ action: "uart_console", params: { baud: 115200, listen_seconds: 6 } })}
          >
            Check UART console
          </button>
          <button
            className="btn-ghost"
            disabled={runModule.isPending}
            onClick={() => runModule.mutate({ action: "power_control", params: { action: "cycle", mode: "optocoupler", off_seconds: 1 } })}
          >
            <Power className="h-4 w-4" /> Power-cycle DUT
          </button>
          <button
            className="btn-warn"
            disabled={runModule.isPending}
            onClick={() => runModule.mutate({ action: "voltage_glitch", params: { on_us: 5000, off_us: 5000, duration_s: 2, mode: "optocoupler" } })}
          >
            <Zap className="h-4 w-4" /> Voltage glitch (gated)
          </button>
        </div>

        {lastAction && <p className="mt-3 text-sm text-emerald-400">{lastAction}</p>}
        <p className="mt-3 text-xs text-slate-500">
          Gated tests need an engagement with a signed Rules of Engagement and{" "}
          <InlineCode>C3I_ENABLE_INVASIVE=true</InlineCode>. Track progress and download
          captures on the <b>Evidence &amp; reports</b> page.
        </p>
      </Card>
    </div>
  );
}
