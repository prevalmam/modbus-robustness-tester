from __future__ import annotations

import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

try:
    import serial
    from serial.tools import list_ports

    SERIAL_AVAILABLE = True
except Exception:
    serial = None
    list_ports = None
    SERIAL_AVAILABLE = False

BAUD_RATES = [1200, 2400, 4800, 9600, 19200, 38400, 57600]
PARITIES = ["None", "ODD", "EVEN"]
DEFAULT_START_ADDRESS = 0
DEFAULT_END_ADDRESS = 10
DEFAULT_MIN_REGS = 1
DEFAULT_MAX_REGS = 10
PORT_WIDTH = 30
RESULT_WIDTH = 55


class ModbusMasterApp:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("Modbus Master")
        self.root.resizable(True, False)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.serial = None
        self.port_var = tk.StringVar()
        self.slave_var = tk.StringVar(value="1")
        self.start_addr_var = tk.StringVar(value=f"{DEFAULT_START_ADDRESS:04d}")
        self.end_addr_var = tk.StringVar(value=f"{DEFAULT_END_ADDRESS:04d}")
        self.min_regs_var = tk.StringVar(value=str(DEFAULT_MIN_REGS))
        self.max_regs_var = tk.StringVar(value=str(DEFAULT_MAX_REGS))
        self.baud_var = tk.StringVar(value=str(BAUD_RATES[3]))
        self.parity_var = tk.StringVar(value=PARITIES[0])
        self.status_var = tk.StringVar(value="Disconnected")
        self.progress_var = tk.StringVar(value="0 / 0")
        self.port_display_to_device: dict[str, str] = {}
        self.stop_event = threading.Event()

        self._build_ui()
        self.refresh_ports()
        self._set_connected_state(False)

        if not SERIAL_AVAILABLE:
            self._disable_for_missing_serial()

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.root, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        ttk.Label(frame, text="Port").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.port_combo = ttk.Combobox(
            frame, textvariable=self.port_var, state="readonly", width=PORT_WIDTH
        )
        self.port_combo.grid(row=0, column=1, sticky="ew", padx=4, pady=4)
        self.refresh_button = ttk.Button(
            frame, text="Refresh", command=self.refresh_ports
        )
        self.refresh_button.grid(row=0, column=2, sticky="w", padx=4, pady=4)

        ttk.Label(frame, text="Slave Addr").grid(
            row=1, column=0, sticky="w", padx=4, pady=4
        )
        self.slave_spin = ttk.Spinbox(
            frame, from_=0, to=247, textvariable=self.slave_var, width=8
        )
        self.slave_spin.grid(row=1, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(frame, text="Start Addr").grid(
            row=2, column=0, sticky="w", padx=4, pady=4
        )
        self.start_addr_spin = ttk.Spinbox(
            frame, from_=0, to=65535, textvariable=self.start_addr_var, width=8
        )
        self.start_addr_spin.grid(row=2, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(frame, text="End Addr").grid(
            row=3, column=0, sticky="w", padx=4, pady=4
        )
        self.end_addr_spin = ttk.Spinbox(
            frame, from_=0, to=65535, textvariable=self.end_addr_var, width=8
        )
        self.end_addr_spin.grid(row=3, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(frame, text="Min Regs").grid(
            row=4, column=0, sticky="w", padx=4, pady=4
        )
        self.min_regs_spin = ttk.Spinbox(
            frame, from_=1, to=125, textvariable=self.min_regs_var, width=8
        )
        self.min_regs_spin.grid(row=4, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(frame, text="Max Regs").grid(
            row=5, column=0, sticky="w", padx=4, pady=4
        )
        self.max_regs_spin = ttk.Spinbox(
            frame, from_=1, to=125, textvariable=self.max_regs_var, width=8
        )
        self.max_regs_spin.grid(row=5, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(frame, text="Baud Rate").grid(
            row=6, column=0, sticky="w", padx=4, pady=4
        )
        self.baud_combo = ttk.Combobox(
            frame,
            textvariable=self.baud_var,
            values=[str(rate) for rate in BAUD_RATES],
            state="readonly",
            width=12,
        )
        self.baud_combo.grid(row=6, column=1, sticky="w", padx=4, pady=4)

        ttk.Label(frame, text="Parity").grid(
            row=7, column=0, sticky="w", padx=4, pady=4
        )
        self.parity_combo = ttk.Combobox(
            frame,
            textvariable=self.parity_var,
            values=PARITIES,
            state="readonly",
            width=10,
        )
        self.parity_combo.grid(row=7, column=1, sticky="w", padx=4, pady=4)

        self.connect_button = ttk.Button(
            frame, text="Connect", command=self.toggle_connection, width=12
        )
        self.connect_button.grid(row=8, column=0, sticky="w", padx=4, pady=10)
        self.send_button = ttk.Button(
            frame, text="Send", command=self.send_read_request, width=12
        )
        self.send_button.grid(row=8, column=1, sticky="w", padx=4, pady=10)

        ttk.Label(frame, text="Log").grid(
            row=9, column=0, sticky="w", padx=4, pady=4
        )
        log_frame = ttk.Frame(frame)
        log_frame.grid(row=9, column=1, columnspan=2, sticky="ew", padx=4, pady=4)
        log_frame.columnconfigure(0, weight=1)
        self.log_text = tk.Text(
            log_frame, height=6, width=RESULT_WIDTH, wrap="none", state="disabled"
        )
        self.log_text.grid(row=0, column=0, sticky="ew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

        ttk.Label(frame, text="Status").grid(
            row=10, column=0, sticky="w", padx=4, pady=4
        )
        self.status_entry = ttk.Entry(
            frame, textvariable=self.status_var, state="readonly", width=RESULT_WIDTH
        )
        self.status_entry.grid(
            row=10, column=1, columnspan=2, sticky="ew", padx=4, pady=4
        )

        ttk.Label(frame, text="Progress").grid(
            row=11, column=0, sticky="w", padx=4, pady=4
        )
        self.progress_entry = ttk.Entry(
            frame, textvariable=self.progress_var, state="readonly", width=RESULT_WIDTH
        )
        self.progress_entry.grid(
            row=11, column=1, columnspan=2, sticky="ew", padx=4, pady=4
        )

        self.readonly_widgets = [self.port_combo, self.baud_combo, self.parity_combo]
        self.toggle_widgets = [
            self.refresh_button,
            self.slave_spin,
            self.start_addr_spin,
            self.end_addr_spin,
            self.min_regs_spin,
            self.max_regs_spin,
        ]

    def _disable_for_missing_serial(self) -> None:
        for widget in self.readonly_widgets + self.toggle_widgets:
            widget.configure(state="disabled")
        self.connect_button.configure(state="disabled")
        self.send_button.configure(state="disabled")
        self.status_var.set("pyserial not installed.")
        self.root.after(
            0,
            lambda: messagebox.showerror(
                "Missing dependency",
                "pyserial is required. Install it with: pip install pyserial",
            ),
        )

    def refresh_ports(self) -> None:
        if not SERIAL_AVAILABLE:
            return
        ports = list_ports.comports()
        self.port_display_to_device = {}
        display_values: list[str] = []
        for port in ports:
            label = f"{port.device} - {port.description}"
            self.port_display_to_device[label] = port.device
            display_values.append(label)
        self.port_combo["values"] = display_values
        current_device = self._selected_device()
        if display_values:
            if current_device:
                matched = next(
                    (
                        label
                        for label, device in self.port_display_to_device.items()
                        if device == current_device
                    ),
                    None,
                )
                if matched:
                    self.port_var.set(matched)
                else:
                    self.port_var.set(display_values[0])
            else:
                self.port_var.set(display_values[0])
        else:
            self.port_var.set("")

    def _set_connected_state(self, connected: bool) -> None:
        for widget in self.readonly_widgets:
            widget.configure(state="disabled" if connected else "readonly")
        for widget in self.toggle_widgets:
            widget.configure(state="disabled" if connected else "normal")
        self.connect_button.configure(text="Disconnect" if connected else "Connect")
        self.send_button.configure(state="normal" if connected else "disabled")
        self.status_var.set("Connected" if connected else "Disconnected")

    def toggle_connection(self) -> None:
        if self.serial and getattr(self.serial, "is_open", False):
            self.stop_event.set()
            self._close_serial()
            self._set_connected_state(False)
            return

        try:
            self._open_serial()
        except Exception as exc:
            messagebox.showerror("Connection error", str(exc))
            self.status_var.set("Connection failed")
            return

        self._set_connected_state(True)

    def _open_serial(self) -> None:
        if not SERIAL_AVAILABLE:
            raise RuntimeError("pyserial is not available.")
        port = self._selected_device()
        if not port:
            raise ValueError("Please select a port.")
        try:
            slave_addr = int(self.slave_var.get())
        except ValueError as exc:
            raise ValueError("Slave address must be a number.") from exc
        if not 0 <= slave_addr <= 247:
            raise ValueError("Slave address must be between 0 and 247.")
        baud_rate = int(self.baud_var.get())
        parity_label = self.parity_var.get()
        parity_map = {
            "None": serial.PARITY_NONE,
            "ODD": serial.PARITY_ODD,
            "EVEN": serial.PARITY_EVEN,
        }
        parity = parity_map.get(parity_label, serial.PARITY_NONE)
        self.serial = serial.Serial(
            port=port,
            baudrate=baud_rate,
            bytesize=serial.EIGHTBITS,
            parity=parity,
            stopbits=serial.STOPBITS_ONE,
            timeout=1.0,
            write_timeout=1.0,
        )

    def _validate_request_range(
        self, start_addr: int, end_addr: int, min_regs: int, max_regs: int
    ) -> None:
        if not 0 <= start_addr <= 0xFFFF:
            raise ValueError("Start address must be between 0 and 65535.")
        if not 0 <= end_addr <= 0xFFFF:
            raise ValueError("End address must be between 0 and 65535.")
        if start_addr > end_addr:
            raise ValueError("Start address must be <= end address.")
        if not 1 <= min_regs <= 125:
            raise ValueError("Min registers must be between 1 and 125.")
        if not 1 <= max_regs <= 125:
            raise ValueError("Max registers must be between 1 and 125.")
        if min_regs > max_regs:
            raise ValueError("Min registers must be <= max registers.")

    def _selected_device(self) -> str:
        selection = self.port_var.get().strip()
        if selection in self.port_display_to_device:
            return self.port_display_to_device[selection]
        return selection

    def _close_serial(self) -> None:
        if self.serial:
            try:
                self.serial.close()
            finally:
                self.serial = None

    def send_read_request(self) -> None:
        if not self.serial or not getattr(self.serial, "is_open", False):
            messagebox.showerror("Not connected", "Please connect to a port first.")
            return
        self.stop_event.clear()
        self.send_button.configure(state="disabled")
        self.status_var.set("Running sequence...")
        self.progress_var.set("0 / 0")
        thread = threading.Thread(target=self._send_read_request, daemon=True)
        thread.start()

    def _send_read_request(self) -> None:
        try:
            slave_addr = int(self.slave_var.get())
            start_addr = int(self.start_addr_var.get())
            end_addr = int(self.end_addr_var.get())
            min_regs = int(self.min_regs_var.get())
            max_regs = int(self.max_regs_var.get())
            self._validate_request_range(start_addr, end_addr, min_regs, max_regs)
            total_requests = (end_addr - start_addr + 1) * (max_regs - min_regs + 1)
            completed_requests = 0
            self.root.after(
                0,
                lambda total=total_requests: self.progress_var.set(f"0 / {total}"),
            )
            for address in range(start_addr, end_addr + 1):
                for quantity in range(min_regs, max_regs + 1):
                    if self.stop_event.is_set():
                        self.root.after(0, self._set_canceled_status_if_connected)
                        return
                    if address + quantity - 1 > 0xFFFF:
                        message = (
                            f"Req {address:04d} x{quantity} -> Error: "
                            "Address range exceeds 0xFFFF"
                        )
                        self.root.after(0, lambda line=message: self._append_log(line))
                        completed_requests += 1
                        self.root.after(
                            0,
                            lambda done=completed_requests, total=total_requests: (
                                self.progress_var.set(f"{done} / {total}")
                            ),
                        )
                        continue
                    try:
                        request = self._build_read_request(slave_addr, address, quantity)
                        self.serial.reset_input_buffer()
                        self.serial.write(request)
                        response = self._read_response()
                        result_text = self._parse_response(response)
                        message = f"Req {address:04d} x{quantity} -> {result_text}"
                        self.root.after(
                            0, lambda line=message: self._append_log(line)
                        )
                    except Exception as exc:
                        if self.stop_event.is_set():
                            self.root.after(0, self._set_canceled_status_if_connected)
                            return
                        message = f"Req {address:04d} x{quantity} -> Error: {exc}"
                        self.root.after(
                            0, lambda line=message: self._append_log(line)
                        )
                    completed_requests += 1
                    self.root.after(
                        0,
                        lambda done=completed_requests, total=total_requests: (
                            self.progress_var.set(f"{done} / {total}")
                        ),
                    )
            self.root.after(
                0,
                lambda: self.status_var.set(
                    f"Sequence done ({total_requests} requests)"
                ),
            )
        except Exception as exc:
            error_text = f"Error: {exc}"
            self.root.after(0, lambda: self._append_log(error_text))
            self.root.after(0, lambda: self.status_var.set(error_text))
        finally:
            self.root.after(0, self._restore_send_state)

    def _build_read_request(self, slave_addr: int, address: int, quantity: int) -> bytes:
        payload = bytearray(
            [
                slave_addr & 0xFF,
                0x03,
                (address >> 8) & 0xFF,
                address & 0xFF,
                (quantity >> 8) & 0xFF,
                quantity & 0xFF,
            ]
        )
        crc = self._crc16(payload)
        payload.extend(crc.to_bytes(2, byteorder="little"))
        return bytes(payload)

    def _read_response(self) -> bytes:
        header = self._read_exact(3)
        if len(header) < 3:
            raise TimeoutError("No response from slave.")
        addr, func, third = header[0], header[1], header[2]
        if func & 0x80:
            rest = self._read_exact(2)
            response = header + rest
        else:
            byte_count = third
            rest = self._read_exact(byte_count + 2)
            response = header + rest
        if len(response) < 5:
            raise TimeoutError("Incomplete response.")
        crc_expected = int.from_bytes(response[-2:], byteorder="little")
        crc_actual = self._crc16(response[:-2])
        if crc_expected != crc_actual:
            raise ValueError("CRC check failed.")
        return response

    def _parse_response(self, response: bytes) -> str:
        addr = response[0]
        func = response[1]
        raw_hex = response.hex(" ").upper()
        if func & 0x80:
            exc_code = response[2]
            return f"Exception from {addr}: 0x{exc_code:02X} | RAW {raw_hex}"
        byte_count = response[2]
        data = response[3 : 3 + byte_count]
        if len(data) % 2 != 0:
            return (
                f"Unexpected data length: {len(data)} bytes | RAW {raw_hex}"
            )
        registers = [
            int.from_bytes(data[offset : offset + 2], byteorder="big")
            for offset in range(0, len(data), 2)
        ]
        hex_value = data.hex(" ").upper()
        hex_registers = ", ".join(f"0x{value:04X}" for value in registers)
        values = ", ".join(str(value) for value in registers)
        return (
            f"Addr {addr} -> [{values}] ({hex_registers}) "
            f"[Data {hex_value}] | RAW {raw_hex}"
        )

    def _read_exact(self, length: int) -> bytes:
        if not self.serial:
            return b""
        data = bytearray()
        deadline = time.monotonic() + 2.0
        while len(data) < length and time.monotonic() < deadline:
            if self.stop_event.is_set():
                break
            chunk = self.serial.read(length - len(data))
            if chunk:
                data.extend(chunk)
        return bytes(data)

    def _set_canceled_status_if_connected(self) -> None:
        if self.serial and getattr(self.serial, "is_open", False):
            self.status_var.set("Canceled by user")

    def _restore_send_state(self) -> None:
        if self.serial and getattr(self.serial, "is_open", False):
            self.send_button.configure(state="normal")
        else:
            self.send_button.configure(state="disabled")

    def _append_log(self, message: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("1.0", message + "\n")
        self.log_text.yview_moveto(0.0)
        self.log_text.configure(state="disabled")

    @staticmethod
    def _crc16(data: bytes) -> int:
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return crc & 0xFFFF

    def run(self) -> None:
        self.root.mainloop()

    def _on_close(self) -> None:
        self.stop_event.set()
        self._close_serial()
        self.root.destroy()


def main() -> None:
    app = ModbusMasterApp()
    app.run()


if __name__ == "__main__":
    main()
