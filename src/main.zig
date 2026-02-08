const std = @import("std");

const PortRange = struct {
    start: u16,
    end: u16,

    fn count(self: PortRange) usize {
        return @as(usize, self.end) - @as(usize, self.start) + 1;
    }
};

const ProbeOutcome = enum(u8) {
    open,
    closed,
    filtered,
    network_unreachable,
    failed,
};

const ConnectStart = enum(u8) {
    connected,
    pending,
    closed,
    filtered,
    network_unreachable,
    failed,
};

const ColorMode = enum(u8) {
    auto,
    always,
    never,
};

const InferenceConfidence = enum(u8) {
    high,
    medium,
    low,
};

const ServiceMatchQuality = enum(u8) {
    guessed,
    port_only,
    banner_only,
    port_and_banner,
};

const OsFamily = enum(u8) {
    windows,
    linux_unix,
    macos_apple,
    appliance_embedded,
    unknown,
};

const DeviceType = enum(u8) {
    printer_mfp,
    server_workstation,
    nas_storage,
    network_appliance,
    iot_embedded,
    unknown,
};

const InferenceResult = struct {
    label: []const u8,
    confidence: InferenceConfidence,
    reason: []const u8,
    score: i32,
    gap: i32,
};

const DeviceScore = struct {
    kind: DeviceType,
    score: i32,
};

const OsScore = struct {
    kind: OsFamily,
    score: i32,
};

const HostDiscoverContext = struct {
    hosts: []const u32,
    statuses: []bool,
    next_index: *std.atomic.Value(usize),
    discovery_ports: []const u16,
    timeout_ms: i32,
};

const PortScanContext = struct {
    ip: [4]u8,
    outcomes: []ProbeOutcome,
    start_port: u16,
    next_index: *std.atomic.Value(usize),
    timeout_ms: i32,
};

const ServiceInfo = struct {
    port: u16,
    name: []const u8,
    banner: []u8,
    details: []u8,
    quality: ServiceMatchQuality,
};

const HostLayer2Info = struct {
    found: bool = false,
    mac: [17]u8 = undefined,
    vendor: []const u8 = "Unknown vendor",
    source: []const u8 = "none",

    fn macSlice(self: HostLayer2Info) []const u8 {
        if (!self.found) return "";
        return self.mac[0..];
    }
};

const MacVendorDb = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap([]const u8),
    loaded: bool = false,

    fn init(allocator: std.mem.Allocator) MacVendorDb {
        return .{
            .allocator = allocator,
            .entries = std.StringHashMap([]const u8).init(allocator),
            .loaded = false,
        };
    }

    fn deinit(self: *MacVendorDb) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit();
    }

    fn vendorForMac(self: *MacVendorDb, mac_text: []const u8) []const u8 {
        self.ensureLoaded();

        var prefix: [6]u8 = undefined;
        if (!normalizeOuiPrefix(mac_text, &prefix)) return "Unknown vendor";
        return self.entries.get(prefix[0..]) orelse "Unknown vendor";
    }

    fn ensureLoaded(self: *MacVendorDb) void {
        if (self.loaded) return;
        self.loaded = true;

        self.loadFromNmapFiles() catch {};
        self.loadFallbackVendors() catch {};
    }

    fn loadFromNmapFiles(self: *MacVendorDb) !void {
        for (nmap_mac_prefix_paths) |path| {
            try self.loadFromNmapFile(path);
        }
    }

    fn loadFromNmapFile(self: *MacVendorDb, path: []const u8) !void {
        const file = if (std.mem.startsWith(u8, path, "/"))
            std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
                error.FileNotFound => return,
                else => return err,
            }
        else
            std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
                error.FileNotFound => return,
                else => return err,
            };
        defer file.close();

        const stat = file.stat() catch |err| return err;
        if (stat.size == 0) return;

        const contents = file.readToEndAlloc(self.allocator, 8 * 1024 * 1024) catch |err| switch (err) {
            error.FileTooBig => return,
            else => return err,
        };
        defer self.allocator.free(contents);

        var lines = std.mem.splitScalar(u8, contents, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;

            var split_at: usize = 0;
            while (split_at < line.len and !std.ascii.isWhitespace(line[split_at])) : (split_at += 1) {}
            const prefix_text = line[0..split_at];

            var vendor_start = split_at;
            while (vendor_start < line.len and std.ascii.isWhitespace(line[vendor_start])) : (vendor_start += 1) {}
            const vendor_text = std.mem.trim(u8, line[vendor_start..], " \t\r");
            if (vendor_text.len == 0) continue;

            var prefix: [6]u8 = undefined;
            if (!normalizeOuiPrefix(prefix_text, &prefix)) continue;
            try self.putVendor(prefix[0..], vendor_text);
        }
    }

    fn loadFallbackVendors(self: *MacVendorDb) !void {
        for (fallback_mac_vendors) |entry| {
            try self.putVendor(entry.prefix, entry.vendor);
        }
    }

    fn putVendor(self: *MacVendorDb, prefix: []const u8, vendor: []const u8) !void {
        if (self.entries.contains(prefix)) return;

        const key_copy = try self.allocator.dupe(u8, prefix);
        errdefer self.allocator.free(key_copy);
        const value_copy = try self.allocator.dupe(u8, vendor);
        errdefer self.allocator.free(value_copy);

        try self.entries.putNoClobber(key_copy, value_copy);
    }
};

const ScanConfig = struct {
    cidr: []const u8,
    ports: PortRange,
    workers: usize,
    timeout_ms: i32,
    max_hosts: usize,
    discovery_ports: []const u16,
    color_mode: ColorMode,
};

const ParsedCidr = struct {
    network: u32,
    prefix: u8,
};

const UiStyle = struct {
    color_enabled: bool,

    fn esc(self: UiStyle, code: []const u8) []const u8 {
        return if (self.color_enabled) code else "";
    }
};

const HostInsight = struct {
    known_services: usize = 0,
    unknown_services: usize = 0,
    banners: usize = 0,
    web: usize = 0,
    file_share: usize = 0,
    print_stack: usize = 0,
    remote_access: usize = 0,
    data_store: usize = 0,
};

const Ansi = struct {
    const reset = "\x1b[0m";
    const bold = "\x1b[1m";
    const dim = "\x1b[2m";
    const cyan = "\x1b[36m";
    const blue = "\x1b[34m";
    const green = "\x1b[32m";
    const yellow = "\x1b[33m";
    const red = "\x1b[31m";
    const magenta = "\x1b[35m";
};

const hr_heavy = "===============================================================================";
const hr_light = "-------------------------------------------------------------------------------";

const default_discovery_ports = [_]u16{ 22, 80, 443, 445, 3389, 5357, 8080, 53 };
const nmap_mac_prefix_paths = [_][]const u8{
    "data/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/usr/share/nmap/nmap-mac-prefixes",
};

const fallback_mac_vendors = [_]struct { prefix: []const u8, vendor: []const u8 }{
    .{ .prefix = "00000C", .vendor = "Cisco Systems" },
    .{ .prefix = "000569", .vendor = "VMware" },
    .{ .prefix = "000C29", .vendor = "VMware" },
    .{ .prefix = "005056", .vendor = "VMware" },
    .{ .prefix = "080027", .vendor = "VirtualBox" },
    .{ .prefix = "525400", .vendor = "QEMU/KVM" },
};

const tls_client_hello = [_]u8{
    0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03, 0x53,
    0x43, 0x41, 0x4e, 0x5f, 0x5a, 0x49, 0x47, 0x4d, 0x41, 0x50, 0x5f, 0x54,
    0x4c, 0x53, 0x5f, 0x50, 0x52, 0x4f, 0x42, 0x45, 0x5f, 0x30, 0x31, 0x02,
    0x03, 0x04, 0x05, 0x06, 0x00, 0x00, 0x04, 0x00, 0x2f, 0x00, 0x35, 0x01,
    0x00, 0x00, 0x00,
};

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const stdout_file = std.fs.File.stdout();
    const stdout_supports_color = stdout_file.getOrEnableAnsiEscapeSupport();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = stdout_file.writer(&stdout_buf);
    const out = &stdout_writer.interface;

    var stderr_buf: [2048]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
    const errw = &stderr_writer.interface;

    run(gpa, out, stdout_supports_color) catch |err| switch (err) {
        error.HelpRequested => {},
        else => {
            try errw.print("error: {s}\n", .{@errorName(err)});
            try printUsage(errw);
            try errw.flush();
            return err;
        },
    };

    try out.flush();
    try errw.flush();
}

fn run(allocator: std.mem.Allocator, out: anytype, stdout_supports_color: bool) !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1) {
        return error.InvalidArguments;
    }

    var discovery_ports = std.ArrayList(u16).empty;
    defer discovery_ports.deinit(allocator);
    try discovery_ports.appendSlice(allocator, &default_discovery_ports);

    var config = ScanConfig{
        .cidr = "",
        .ports = .{ .start = 1, .end = 65535 },
        .workers = defaultWorkerCount(),
        .timeout_ms = 180,
        .max_hosts = 65536,
        .discovery_ports = discovery_ports.items,
        .color_mode = .auto,
    };

    try parseCliArgs(allocator, args[1..], &config, &discovery_ports, out);
    config.discovery_ports = discovery_ports.items;

    if (config.cidr.len == 0) return error.MissingCIDR;
    if (config.discovery_ports.len == 0) return error.MissingDiscoveryPorts;

    const style = UiStyle{
        .color_enabled = resolveColor(config.color_mode, stdout_supports_color),
    };

    const parsed_cidr = try parseCidr(config.cidr);
    const candidate_hosts = try enumerateHosts(allocator, parsed_cidr, config.max_hosts);
    defer allocator.free(candidate_hosts);

    if (candidate_hosts.len == 0) {
        try out.print("No hosts in requested CIDR after filters.\n", .{});
        return;
    }

    const scan_start_ms = std.time.milliTimestamp();
    try printScanPreamble(out, style, config, candidate_hosts.len);

    const alive_hosts = try discoverHosts(
        allocator,
        candidate_hosts,
        config.discovery_ports,
        config.workers,
        config.timeout_ms,
    );
    defer allocator.free(alive_hosts);

    const discover_done_ms = std.time.milliTimestamp();
    const discovery_ms = discover_done_ms - scan_start_ms;

    try printDiscoverySummary(out, style, alive_hosts.len, candidate_hosts.len, discovery_ms);
    if (alive_hosts.len == 0) {
        try out.print("No reachable hosts found.\n", .{});
        return;
    }

    var mac_vendor_db = MacVendorDb.init(allocator);
    defer mac_vendor_db.deinit();

    var total_open_ports: usize = 0;
    var hosts_with_unknown: usize = 0;
    var uncertain_os_hosts: usize = 0;

    for (alive_hosts, 0..) |host_u32, host_index| {
        const host_scan_start = std.time.milliTimestamp();

        const ip = u32ToIp(host_u32);
        var ip_buf: [16]u8 = undefined;
        const ip_text = try ipToString(ip, &ip_buf);

        const open_ports = try scanOpenPorts(
            allocator,
            ip,
            config.ports,
            config.workers,
            config.timeout_ms,
        );
        defer allocator.free(open_ports);

        const services = try detectServices(
            allocator,
            ip,
            open_ports,
            config.timeout_ms,
        );
        defer {
            for (services) |svc| {
                allocator.free(svc.banner);
                allocator.free(svc.details);
            }
            allocator.free(services);
        }

        const insight = analyzeHost(services);
        const l2_info = resolveHostLayer2(allocator, &mac_vendor_db, ip_text);
        const device_guess = inferDeviceType(services, insight, l2_info);
        const os_guess = inferOs(services, insight, l2_info, device_guess);
        const host_elapsed_ms = std.time.milliTimestamp() - host_scan_start;

        total_open_ports += open_ports.len;
        if (insight.unknown_services > 0) hosts_with_unknown += 1;
        if (os_guess.confidence == .low or std.mem.eql(u8, os_guess.label, "Unknown")) {
            uncertain_os_hosts += 1;
        }

        try printHostReport(
            out,
            style,
            host_index + 1,
            alive_hosts.len,
            ip_text,
            open_ports,
            services,
            insight,
            l2_info,
            device_guess,
            os_guess,
            host_elapsed_ms,
        );
    }

    const done_ms = std.time.milliTimestamp();
    const elapsed_ms = done_ms - scan_start_ms;
    try printFinalSummary(
        out,
        style,
        alive_hosts.len,
        candidate_hosts.len,
        total_open_ports,
        hosts_with_unknown,
        uncertain_os_hosts,
        elapsed_ms,
    );
}

fn parseCliArgs(
    allocator: std.mem.Allocator,
    args: []const [:0]u8,
    config: *ScanConfig,
    discovery_ports: *std.ArrayList(u16),
    out: anytype,
) !void {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i][0..args[i].len];

        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printUsage(out);
            return error.HelpRequested;
        } else if (std.mem.eql(u8, arg, "--cidr")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.cidr = args[i][0..args[i].len];
        } else if (std.mem.eql(u8, arg, "--ports")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.ports = try parsePortRange(args[i][0..args[i].len]);
        } else if (std.mem.eql(u8, arg, "--workers")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.workers = try std.fmt.parseUnsigned(usize, args[i][0..args[i].len], 10);
            if (config.workers == 0) return error.InvalidWorkers;
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.timeout_ms = try std.fmt.parseInt(i32, args[i][0..args[i].len], 10);
            if (config.timeout_ms <= 0) return error.InvalidTimeout;
        } else if (std.mem.eql(u8, arg, "--max-hosts")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            config.max_hosts = try std.fmt.parseUnsigned(usize, args[i][0..args[i].len], 10);
            if (config.max_hosts == 0) return error.InvalidHostLimit;
        } else if (std.mem.eql(u8, arg, "--discovery-ports")) {
            i += 1;
            if (i >= args.len) return error.MissingValue;
            discovery_ports.clearRetainingCapacity();
            try parseDiscoveryPorts(allocator, args[i][0..args[i].len], discovery_ports);
        } else if (std.mem.eql(u8, arg, "--color")) {
            config.color_mode = .always;
        } else if (std.mem.eql(u8, arg, "--no-color")) {
            config.color_mode = .never;
        } else if (std.mem.startsWith(u8, arg, "--")) {
            return error.UnknownArgument;
        } else if (config.cidr.len == 0) {
            config.cidr = arg;
        } else {
            return error.UnknownArgument;
        }
    }
}

fn parseDiscoveryPorts(
    allocator: std.mem.Allocator,
    raw: []const u8,
    discovery_ports: *std.ArrayList(u16),
) !void {
    var iter = std.mem.splitScalar(u8, raw, ',');
    while (iter.next()) |token_raw| {
        const token = std.mem.trim(u8, token_raw, " \t");
        if (token.len == 0) continue;
        const port = try std.fmt.parseUnsigned(u16, token, 10);
        if (port == 0) return error.InvalidPort;
        try discovery_ports.append(allocator, port);
    }
}

fn parseCidr(cidr_text: []const u8) !ParsedCidr {
    var parts = std.mem.splitScalar(u8, cidr_text, '/');
    const ip_text = parts.next() orelse return error.InvalidCIDR;
    const prefix_text = parts.next() orelse return error.InvalidCIDR;
    if (parts.next() != null) return error.InvalidCIDR;

    const addr = try std.net.Address.parseIp4(ip_text, 0);
    const bytes: *const [4]u8 = @ptrCast(&addr.in.sa.addr);
    const ip_u32 = ipToU32(bytes.*);

    const prefix = try std.fmt.parseUnsigned(u8, prefix_text, 10);
    if (prefix > 32) return error.InvalidCIDRPrefix;

    const mask = prefixToMask(prefix);
    return .{
        .network = ip_u32 & mask,
        .prefix = prefix,
    };
}

fn enumerateHosts(
    allocator: std.mem.Allocator,
    cidr: ParsedCidr,
    max_hosts: usize,
) ![]u32 {
    const mask = prefixToMask(cidr.prefix);
    const network = cidr.network & mask;
    const broadcast = network | ~mask;

    var first: u32 = network;
    var last: u32 = broadcast;

    if (cidr.prefix < 31) {
        first = network + 1;
        last = broadcast - 1;
    }

    if (last < first) return allocator.alloc(u32, 0);

    const total_u64 = @as(u64, last) - @as(u64, first) + 1;
    const capped_u64 = @min(total_u64, @as(u64, max_hosts));
    const capped: usize = @intCast(capped_u64);

    const hosts = try allocator.alloc(u32, capped);
    for (0..capped) |idx| {
        hosts[idx] = first + @as(u32, @intCast(idx));
    }
    return hosts;
}

fn prefixToMask(prefix: u8) u32 {
    if (prefix == 0) return 0;
    return @as(u32, 0xFFFF_FFFF) << @as(u5, @intCast(32 - prefix));
}

fn discoverHosts(
    allocator: std.mem.Allocator,
    candidates: []const u32,
    discovery_ports: []const u16,
    workers: usize,
    timeout_ms: i32,
) ![]u32 {
    if (candidates.len == 0) return allocator.alloc(u32, 0);

    const statuses = try allocator.alloc(bool, candidates.len);
    defer allocator.free(statuses);
    @memset(statuses, false);

    const thread_count = effectiveWorkerCount(workers, candidates.len);
    var threads = try allocator.alloc(std.Thread, thread_count);
    defer allocator.free(threads);

    var next_index = std.atomic.Value(usize).init(0);

    var ctx = HostDiscoverContext{
        .hosts = candidates,
        .statuses = statuses,
        .next_index = &next_index,
        .discovery_ports = discovery_ports,
        .timeout_ms = timeout_ms,
    };

    var spawned: usize = 0;
    errdefer {
        for (threads[0..spawned]) |t| t.join();
    }

    while (spawned < thread_count) : (spawned += 1) {
        threads[spawned] = try std.Thread.spawn(.{}, hostDiscoverWorker, .{&ctx});
    }

    for (threads[0..spawned]) |t| t.join();

    var alive = std.ArrayList(u32).empty;
    defer alive.deinit(allocator);

    for (statuses, 0..) |up, idx| {
        if (up) try alive.append(allocator, candidates[idx]);
    }

    return alive.toOwnedSlice(allocator);
}

fn hostDiscoverWorker(ctx: *HostDiscoverContext) void {
    while (true) {
        const idx = ctx.next_index.fetchAdd(1, .monotonic);
        if (idx >= ctx.hosts.len) return;

        const ip = u32ToIp(ctx.hosts[idx]);
        var up = false;

        for (ctx.discovery_ports) |port| {
            const probe = tcpProbe(ip, port, ctx.timeout_ms);
            if (probe == .open or probe == .closed) {
                up = true;
                break;
            }
        }

        ctx.statuses[idx] = up;
    }
}

fn scanOpenPorts(
    allocator: std.mem.Allocator,
    ip: [4]u8,
    range: PortRange,
    workers: usize,
    timeout_ms: i32,
) ![]u16 {
    const port_count = range.count();
    const outcomes = try allocator.alloc(ProbeOutcome, port_count);
    defer allocator.free(outcomes);
    @memset(outcomes, .filtered);

    const thread_count = effectiveWorkerCount(workers, port_count);
    var threads = try allocator.alloc(std.Thread, thread_count);
    defer allocator.free(threads);

    var next_index = std.atomic.Value(usize).init(0);
    var ctx = PortScanContext{
        .ip = ip,
        .outcomes = outcomes,
        .start_port = range.start,
        .next_index = &next_index,
        .timeout_ms = timeout_ms,
    };

    var spawned: usize = 0;
    errdefer {
        for (threads[0..spawned]) |t| t.join();
    }

    while (spawned < thread_count) : (spawned += 1) {
        threads[spawned] = try std.Thread.spawn(.{}, portScanWorker, .{&ctx});
    }

    for (threads[0..spawned]) |t| t.join();

    var open_ports = std.ArrayList(u16).empty;
    defer open_ports.deinit(allocator);

    for (outcomes, 0..) |outcome, idx| {
        if (outcome == .open) {
            const port = range.start + @as(u16, @intCast(idx));
            try open_ports.append(allocator, port);
        }
    }

    return open_ports.toOwnedSlice(allocator);
}

fn portScanWorker(ctx: *PortScanContext) void {
    while (true) {
        const idx = ctx.next_index.fetchAdd(1, .monotonic);
        if (idx >= ctx.outcomes.len) return;

        const port = ctx.start_port + @as(u16, @intCast(idx));
        ctx.outcomes[idx] = tcpProbe(ctx.ip, port, ctx.timeout_ms);
    }
}

fn tcpProbe(ip: [4]u8, port: u16, timeout_ms: i32) ProbeOutcome {
    var addr = std.net.Address.initIp4(ip, port);
    const sock = std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK,
        std.posix.IPPROTO.TCP,
    ) catch {
        return .failed;
    };
    defer std.posix.close(sock);

    return switch (startNonblockingConnect(sock, &addr)) {
        .connected => .open,
        .pending => probeSocketConnectResult(sock, timeout_ms),
        .closed => .closed,
        .filtered => .filtered,
        .network_unreachable => .network_unreachable,
        .failed => .failed,
    };
}

fn probeSocketConnectResult(sock: std.posix.socket_t, timeout_ms: i32) ProbeOutcome {
    var fds = [_]std.posix.pollfd{
        .{
            .fd = sock,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        },
    };

    const ready = std.posix.poll(&fds, timeout_ms) catch {
        return .failed;
    };
    if (ready == 0) return .filtered;

    var so_error: i32 = 0;
    std.posix.getsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.ERROR, std.mem.asBytes(&so_error)) catch {
        return .failed;
    };
    return classifyErrnoCode(so_error);
}

fn detectServices(
    allocator: std.mem.Allocator,
    ip: [4]u8,
    open_ports: []const u16,
    timeout_ms: i32,
) ![]ServiceInfo {
    var services = std.ArrayList(ServiceInfo).empty;
    errdefer {
        for (services.items) |svc| {
            allocator.free(svc.banner);
            allocator.free(svc.details);
        }
        services.deinit(allocator);
    }

    for (open_ports) |port| {
        const banner = try grabBanner(allocator, ip, port, timeout_ms);
        const fingerprint = fingerprintService(port, banner);
        const details = try buildServiceDetails(allocator, ip, port, fingerprint.name, banner, timeout_ms);
        try services.append(allocator, .{
            .port = port,
            .name = fingerprint.name,
            .banner = banner,
            .details = details,
            .quality = fingerprint.quality,
        });
    }

    return services.toOwnedSlice(allocator);
}

fn buildServiceDetails(
    allocator: std.mem.Allocator,
    ip: [4]u8,
    port: u16,
    service_name: []const u8,
    banner: []const u8,
    timeout_ms: i32,
) ![]u8 {
    var details = std.ArrayList(u8).empty;
    defer details.deinit(allocator);

    if (shouldProbeHttpMetadata(port, service_name, banner)) {
        const http_details = try probeHttpMetadata(allocator, ip, port, timeout_ms);
        defer allocator.free(http_details);
        if (http_details.len > 0) {
            try appendDetailSection(allocator, &details, http_details);
        }
    }

    if (shouldProbeTlsMetadata(port, service_name, banner)) {
        const tls_details = try probeTlsMetadata(allocator, ip, port, timeout_ms);
        defer allocator.free(tls_details);
        if (tls_details.len > 0) {
            try appendDetailSection(allocator, &details, tls_details);
        }
    }

    if (details.items.len == 0) return allocator.dupe(u8, "");
    return details.toOwnedSlice(allocator);
}

fn appendDetailSection(
    allocator: std.mem.Allocator,
    details: *std.ArrayList(u8),
    section: []const u8,
) !void {
    if (details.items.len > 0) try details.appendSlice(allocator, " | ");
    try details.appendSlice(allocator, section);
}

fn shouldProbeHttpMetadata(port: u16, service_name: []const u8, banner: []const u8) bool {
    if (containsIgnoreCase(banner, "http/")) return true;
    if (std.mem.eql(u8, service_name, "http") or
        std.mem.eql(u8, service_name, "http-proxy") or
        std.mem.eql(u8, service_name, "ipp"))
    {
        return true;
    }

    return switch (port) {
        80, 81, 631, 8000, 8006, 8080, 8081, 8888, 9000 => true,
        else => false,
    };
}

fn shouldProbeTlsMetadata(port: u16, service_name: []const u8, banner: []const u8) bool {
    if (isLikelyTlsPort(port)) return true;
    if (std.mem.eql(u8, service_name, "https") or std.mem.eql(u8, service_name, "tls-service")) return true;
    return containsIgnoreCase(banner, "[tls binary record]");
}

fn probeHttpMetadata(
    allocator: std.mem.Allocator,
    ip: [4]u8,
    port: u16,
    timeout_ms: i32,
) ![]u8 {
    const sock = openSocketWithTimeout(ip, port, timeout_ms) orelse {
        return allocator.dupe(u8, "");
    };
    defer std.posix.close(sock);

    const request =
        "GET / HTTP/1.0\r\n" ++
        "Host: zigmap\r\n" ++
        "User-Agent: zigmap/0.1\r\n" ++
        "Connection: close\r\n\r\n";

    _ = std.posix.send(sock, request, 0) catch {
        return allocator.dupe(u8, "");
    };

    var raw: [4096]u8 = undefined;
    var used: usize = 0;
    var wait_ms = timeout_ms;

    while (used < raw.len) {
        var fds = [_]std.posix.pollfd{
            .{
                .fd = sock,
                .events = std.posix.POLL.IN,
                .revents = 0,
            },
        };
        const ready = std.posix.poll(&fds, wait_ms) catch break;
        if (ready == 0) break;
        wait_ms = 40;

        const n = std.posix.recv(sock, raw[used..], 0) catch |err| switch (err) {
            error.WouldBlock => break,
            else => break,
        };
        if (n == 0) break;
        used += n;

        if (std.mem.indexOf(u8, raw[0..used], "\r\n\r\n") != null and used > 2048) break;
    }

    if (used == 0) return allocator.dupe(u8, "");
    return summarizeHttpResponse(allocator, raw[0..used]);
}

fn summarizeHttpResponse(allocator: std.mem.Allocator, response: []const u8) ![]u8 {
    var details = std.ArrayList(u8).empty;
    defer details.deinit(allocator);

    const Split = struct {
        idx: usize,
        sep_len: usize,
    };
    const split: Split = blk: {
        if (std.mem.indexOf(u8, response, "\r\n\r\n")) |idx| {
            break :blk .{ .idx = idx, .sep_len = @as(usize, 4) };
        }
        if (std.mem.indexOf(u8, response, "\n\n")) |idx| {
            break :blk .{ .idx = idx, .sep_len = @as(usize, 2) };
        }
        break :blk .{ .idx = response.len, .sep_len = @as(usize, 0) };
    };

    const headers = response[0..split.idx];
    const body_start = @min(split.idx + split.sep_len, response.len);
    const body = response[body_start..];

    var line_iter = std.mem.splitScalar(u8, headers, '\n');
    if (line_iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, "\r\t ");
        if (line.len > 0 and containsIgnoreCase(line, "http/")) {
            try appendNamedDetail(allocator, &details, "status", line, 72);
        }
    }

    if (extractHttpHeaderValue(headers, "Server")) |server| {
        try appendNamedDetail(allocator, &details, "server", server, 64);
    }
    if (extractHttpHeaderValue(headers, "Location")) |location| {
        try appendNamedDetail(allocator, &details, "location", location, 80);
    }
    if (extractHttpHeaderValue(headers, "WWW-Authenticate")) |auth| {
        try appendNamedDetail(allocator, &details, "auth", auth, 72);
    }

    if (extractHtmlTitle(body)) |title| {
        try appendNamedDetail(allocator, &details, "title", title, 72);
    }

    if (details.items.len == 0) return allocator.dupe(u8, "");
    return details.toOwnedSlice(allocator);
}

fn extractHttpHeaderValue(headers: []const u8, target_name: []const u8) ?[]const u8 {
    var line_iter = std.mem.splitScalar(u8, headers, '\n');
    while (line_iter.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, "\r");
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, target_name)) continue;
        return std.mem.trim(u8, line[colon + 1 ..], " \t\r");
    }
    return null;
}

fn extractHtmlTitle(body: []const u8) ?[]const u8 {
    const open_idx = indexOfIgnoreCase(body, "<title>") orelse return null;
    const start = open_idx + "<title>".len;
    const close_rel = indexOfIgnoreCase(body[start..], "</title>") orelse return null;
    return std.mem.trim(u8, body[start .. start + close_rel], " \t\r\n");
}

fn appendNamedDetail(
    allocator: std.mem.Allocator,
    details: *std.ArrayList(u8),
    key: []const u8,
    value: []const u8,
    max_value_len: usize,
) !void {
    if (details.items.len > 0) try details.appendSlice(allocator, "; ");
    try details.appendSlice(allocator, key);
    try details.appendSlice(allocator, "=");

    var buf: [256]u8 = undefined;
    const clean = sanitizeSnippet(value, buf[0..], max_value_len);
    try details.appendSlice(allocator, clean);
}

fn sanitizeSnippet(input: []const u8, out: []u8, max_len: usize) []const u8 {
    var write_idx: usize = 0;
    var prev_space = false;

    for (input) |c| {
        if (write_idx >= out.len or write_idx >= max_len) break;
        if (c >= 32 and c <= 126) {
            out[write_idx] = c;
            prev_space = false;
            write_idx += 1;
        } else if (c == '\r' or c == '\n' or c == '\t') {
            if (prev_space or write_idx == 0) continue;
            out[write_idx] = ' ';
            prev_space = true;
            write_idx += 1;
        }
    }

    while (write_idx > 0 and out[write_idx - 1] == ' ') : (write_idx -= 1) {}
    return out[0..write_idx];
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (haystack.len < needle.len) return null;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) break;
        }
        if (j == needle.len) return i;
    }
    return null;
}

fn probeTlsMetadata(
    allocator: std.mem.Allocator,
    ip: [4]u8,
    port: u16,
    timeout_ms: i32,
) ![]u8 {
    const sock = openSocketWithTimeout(ip, port, timeout_ms) orelse {
        return allocator.dupe(u8, "");
    };
    defer std.posix.close(sock);

    _ = std.posix.send(sock, &tls_client_hello, 0) catch {
        return allocator.dupe(u8, "");
    };

    var fds = [_]std.posix.pollfd{
        .{
            .fd = sock,
            .events = std.posix.POLL.IN,
            .revents = 0,
        },
    };
    const ready = std.posix.poll(&fds, timeout_ms) catch {
        return allocator.dupe(u8, "");
    };
    if (ready == 0) return allocator.dupe(u8, "");

    var response: [128]u8 = undefined;
    const n = std.posix.recv(sock, response[0..], 0) catch {
        return allocator.dupe(u8, "");
    };
    if (n < 5) return allocator.dupe(u8, "");

    const record_type = tlsRecordTypeName(response[0]);
    const version_name = tlsVersionName(response[1], response[2]);
    const handshake_name = if (response[0] == 0x16 and n >= 6) tlsHandshakeTypeName(response[5]) else "n/a";

    return std.fmt.allocPrint(
        allocator,
        "tls_record={s}; tls_ver={s}; hs={s}",
        .{ record_type, version_name, handshake_name },
    );
}

fn tlsRecordTypeName(code: u8) []const u8 {
    return switch (code) {
        0x14 => "change-cipher-spec",
        0x15 => "alert",
        0x16 => "handshake",
        0x17 => "application-data",
        else => "unknown",
    };
}

fn tlsVersionName(major: u8, minor: u8) []const u8 {
    if (major != 0x03) return "non-tls";
    return switch (minor) {
        0x00 => "SSLv3",
        0x01 => "TLS1.0",
        0x02 => "TLS1.1",
        0x03 => "TLS1.2/1.3",
        0x04 => "TLS1.3",
        else => "TLS(unknown)",
    };
}

fn tlsHandshakeTypeName(code: u8) []const u8 {
    return switch (code) {
        0x02 => "server-hello",
        0x0b => "certificate",
        0x0e => "server-hello-done",
        else => "other",
    };
}

fn grabBanner(
    allocator: std.mem.Allocator,
    ip: [4]u8,
    port: u16,
    timeout_ms: i32,
) ![]u8 {
    const sock = openSocketWithTimeout(ip, port, timeout_ms) orelse {
        return allocator.dupe(u8, "");
    };
    defer std.posix.close(sock);

    if (portProbeRequest(port)) |payload| {
        _ = std.posix.send(sock, payload, 0) catch {};
    }

    var fds = [_]std.posix.pollfd{
        .{
            .fd = sock,
            .events = std.posix.POLL.IN,
            .revents = 0,
        },
    };

    const ready = std.posix.poll(&fds, timeout_ms) catch {
        return allocator.dupe(u8, "");
    };
    if (ready == 0) return allocator.dupe(u8, "");

    var buf: [512]u8 = undefined;
    const n = std.posix.recv(sock, buf[0..], 0) catch {
        return allocator.dupe(u8, "");
    };
    if (n == 0) return allocator.dupe(u8, "");

    return sanitizeBanner(allocator, buf[0..n]);
}

fn openSocketWithTimeout(ip: [4]u8, port: u16, timeout_ms: i32) ?std.posix.socket_t {
    var addr = std.net.Address.initIp4(ip, port);
    const sock = std.posix.socket(
        std.posix.AF.INET,
        std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK,
        std.posix.IPPROTO.TCP,
    ) catch {
        return null;
    };

    switch (startNonblockingConnect(sock, &addr)) {
        .connected => return sock,
        .pending => {},
        else => {
            std.posix.close(sock);
            return null;
        },
    }

    const result = probeSocketConnectResult(sock, timeout_ms);
    if (result != .open) {
        std.posix.close(sock);
        return null;
    }

    return sock;
}

fn sanitizeBanner(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    for (input) |c| {
        if (out.items.len >= 180) break;
        if (c >= 32 and c <= 126) {
            try out.append(allocator, c);
        } else if (c == '\r' or c == '\n' or c == '\t') {
            if (out.items.len == 0 or out.items[out.items.len - 1] == ' ') continue;
            try out.append(allocator, ' ');
        }
    }

    const trimmed = std.mem.trim(u8, out.items, " ");
    if (trimmed.len == 0) {
        if (binaryProtocolMarker(input)) |marker| {
            return allocator.dupe(u8, marker);
        }
    }
    return allocator.dupe(u8, trimmed);
}

fn startNonblockingConnect(sock: std.posix.socket_t, addr: *const std.net.Address) ConnectStart {
    const rc = std.posix.system.connect(sock, &addr.any, addr.getOsSockLen());
    const err = std.posix.errno(rc);

    if (err == .SUCCESS) return .connected;
    if (errnoEnumMatches(err, "INPROGRESS") or errnoEnumMatches(err, "AGAIN") or errnoEnumMatches(err, "ALREADY")) {
        return .pending;
    }

    return switch (classifyErrnoEnum(err)) {
        .closed => .closed,
        .filtered => .filtered,
        .network_unreachable => .network_unreachable,
        else => .failed,
    };
}

fn classifyErrnoCode(so_error: i32) ProbeOutcome {
    if (so_error == 0) return .open;
    if (errnoCodeMatches(so_error, "CONNREFUSED") or errnoCodeMatches(so_error, "CONNRESET")) return .closed;
    if (errnoCodeMatches(so_error, "TIMEDOUT") or
        errnoCodeMatches(so_error, "AGAIN") or
        errnoCodeMatches(so_error, "INPROGRESS") or
        errnoCodeMatches(so_error, "ALREADY"))
    {
        return .filtered;
    }
    if (isUnreachableErrCode(so_error)) return .network_unreachable;
    return .failed;
}

fn classifyErrnoEnum(err: std.posix.E) ProbeOutcome {
    if (errnoEnumMatches(err, "CONNREFUSED") or errnoEnumMatches(err, "CONNRESET")) return .closed;
    if (errnoEnumMatches(err, "TIMEDOUT")) return .filtered;
    if (isUnreachableErrEnum(err)) return .network_unreachable;
    return .failed;
}

fn isUnreachableErrEnum(err: std.posix.E) bool {
    return errnoEnumMatches(err, "HOSTUNREACH") or
        errnoEnumMatches(err, "NETUNREACH") or
        errnoEnumMatches(err, "HOSTDOWN") or
        errnoEnumMatches(err, "NETDOWN");
}

fn isUnreachableErrCode(so_error: i32) bool {
    return errnoCodeMatches(so_error, "HOSTUNREACH") or
        errnoCodeMatches(so_error, "NETUNREACH") or
        errnoCodeMatches(so_error, "HOSTDOWN") or
        errnoCodeMatches(so_error, "NETDOWN");
}

fn errnoEnumMatches(err: std.posix.E, comptime tag_name: []const u8) bool {
    if (!@hasField(std.posix.E, tag_name)) return false;
    return err == @field(std.posix.E, tag_name);
}

fn errnoCodeMatches(so_error: i32, comptime tag_name: []const u8) bool {
    if (!@hasField(std.posix.E, tag_name)) return false;
    return so_error == @as(i32, @intFromEnum(@field(std.posix.E, tag_name)));
}

fn binaryProtocolMarker(input: []const u8) ?[]const u8 {
    if (input.len >= 3 and (input[0] == 0x14 or input[0] == 0x15 or input[0] == 0x16) and input[1] == 0x03) {
        return "[TLS binary record]";
    }
    if (input.len >= 4 and (input[0] == 0xFF or input[0] == 0xFE) and input[1] == 'S' and input[2] == 'M' and input[3] == 'B') {
        return "[SMB binary record]";
    }
    return null;
}

fn portProbeRequest(port: u16) ?[]const u8 {
    return switch (port) {
        25 => "EHLO zigmap.local\r\n",
        80, 81, 443, 631, 8000, 8080, 8081, 8443, 8888 => "HEAD / HTTP/1.0\r\nHost: zigmap\r\nConnection: close\r\n\r\n",
        110 => "CAPA\r\n",
        143 => "a1 CAPABILITY\r\n",
        1865 => "INFO\r\n",
        6379 => "PING\r\n",
        9100 => "\x1b%-12345X@PJL INFO ID\r\n",
        else => null,
    };
}

fn knownServiceName(port: u16) []const u8 {
    return switch (port) {
        20, 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67, 68 => "dhcp",
        69 => "tftp",
        80 => "http",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137, 138, 139 => "netbios",
        143 => "imap",
        161, 162 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        465 => "smtps",
        514 => "syslog",
        515 => "printer",
        548 => "afp",
        587 => "submission",
        631 => "ipp",
        9100 => "jetdirect",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        1723 => "pptp",
        1883 => "mqtt",
        2049 => "nfs",
        2375, 2376 => "docker",
        3306 => "mysql",
        3389 => "rdp",
        5000, 5001 => "upnp/http-alt",
        5432 => "postgresql",
        5672 => "amqp",
        5900 => "vnc",
        5985, 5986 => "winrm",
        6379 => "redis",
        6443 => "k8s-api",
        7001 => "weblogic",
        8006 => "proxmox",
        8080 => "http-proxy",
        8443 => "https-alt",
        9000 => "sonarqube/http-alt",
        9092 => "kafka",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        else => "unknown",
    };
}

const ServiceFingerprint = struct {
    name: []const u8,
    quality: ServiceMatchQuality,
};

fn fingerprintService(port: u16, banner: []const u8) ServiceFingerprint {
    const by_port = knownServiceName(port);
    const by_banner = serviceNameFromBanner(banner);

    if (by_banner) |banner_name| {
        if (!std.mem.eql(u8, by_port, "unknown")) {
            if (std.mem.eql(u8, by_port, banner_name)) {
                return .{ .name = by_port, .quality = .port_and_banner };
            }
            // Keep TLS-oriented labels on canonical TLS ports even if plaintext banner parsing says http.
            if (isLikelyTlsPort(port) and std.mem.eql(u8, by_port, "https") and std.mem.eql(u8, banner_name, "http")) {
                return .{ .name = by_port, .quality = .port_only };
            }
            return .{ .name = banner_name, .quality = .port_and_banner };
        }
        return .{ .name = banner_name, .quality = .banner_only };
    }

    if (!std.mem.eql(u8, by_port, "unknown")) {
        return .{ .name = by_port, .quality = .port_only };
    }

    if (isLikelyTlsPort(port)) {
        return .{ .name = "tls-service", .quality = .guessed };
    }

    return .{ .name = "unknown", .quality = .guessed };
}

fn serviceNameFromBanner(banner: []const u8) ?[]const u8 {
    if (banner.len == 0) return null;

    if (containsAnyIgnoreCase(banner, &.{
        "ssh-",
        "openssh",
    })) return "ssh";

    if (containsAnyIgnoreCase(banner, &.{
        "smtp",
        "esmtp",
    })) return "smtp";

    if (containsAnyIgnoreCase(banner, &.{
        "imap",
        "capability imap",
    })) return "imap";

    if (containsAnyIgnoreCase(banner, &.{
        "pop3",
        "capa",
    })) return "pop3";

    if (containsAnyIgnoreCase(banner, &.{
        "redis",
        "+pong",
    })) return "redis";

    if (containsAnyIgnoreCase(banner, &.{
        "mysql",
        "mariadb",
    })) return "mysql";

    if (containsAnyIgnoreCase(banner, &.{
        "postgresql",
        "postgres",
    })) return "postgresql";

    if (containsAnyIgnoreCase(banner, &.{
        "mongodb",
    })) return "mongodb";

    if (containsAnyIgnoreCase(banner, &.{
        "@pjl",
        "jetdirect",
    })) return "jetdirect";

    if (containsAnyIgnoreCase(banner, &.{
        "ipp",
        "internet printing protocol",
        "cups",
        "airprint",
    })) return "ipp";

    if (containsAnyIgnoreCase(banner, &.{
        "[tls binary record]",
        "ssl",
        "tls",
    })) return "tls-service";

    if (containsAnyIgnoreCase(banner, &.{
        "[smb binary record]",
        "smb",
        "netbios",
        "microsoft-ds",
    })) return "microsoft-ds";

    if (containsAnyIgnoreCase(banner, &.{
        "http/1.",
        "http/2",
        "server:",
    })) return "http";

    return null;
}

fn isLikelyTlsPort(port: u16) bool {
    return switch (port) {
        443, 465, 636, 853, 993, 995, 5986, 8443, 9443 => true,
        else => false,
    };
}

fn resolveHostLayer2(
    allocator: std.mem.Allocator,
    vendor_db: *MacVendorDb,
    ip_text: []const u8,
) HostLayer2Info {
    var info = HostLayer2Info{};

    var mac: [17]u8 = undefined;
    const arp_argv = [_][]const u8{ "arp", "-n", ip_text };
    if (tryResolveMacWithCommand(allocator, &arp_argv, &mac)) {
        info.found = true;
        info.mac = mac;
        info.vendor = vendor_db.vendorForMac(info.macSlice());
        info.source = "arp";
        return info;
    }

    const ip_neigh_argv = [_][]const u8{ "ip", "neigh", "show", ip_text };
    if (tryResolveMacWithCommand(allocator, &ip_neigh_argv, &mac)) {
        info.found = true;
        info.mac = mac;
        info.vendor = vendor_db.vendorForMac(info.macSlice());
        info.source = "ip-neigh";
        return info;
    }

    return info;
}

fn tryResolveMacWithCommand(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    mac_out: *[17]u8,
) bool {
    const run_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 8 * 1024,
    }) catch return false;
    defer allocator.free(run_result.stdout);
    defer allocator.free(run_result.stderr);

    if (parseMacFromText(run_result.stdout)) |mac| {
        mac_out.* = mac;
        return true;
    }
    if (parseMacFromText(run_result.stderr)) |mac| {
        mac_out.* = mac;
        return true;
    }
    return false;
}

fn parseMacFromText(text: []const u8) ?[17]u8 {
    if (text.len < 17) return null;

    var i: usize = 0;
    while (i + 17 <= text.len) : (i += 1) {
        const sep = text[i + 2];
        if (sep != ':' and sep != '-') continue;
        if (i > 0 and isHexAscii(text[i - 1])) continue;
        if (i + 17 < text.len and isHexAscii(text[i + 17])) continue;

        var out: [17]u8 = undefined;
        var ok = true;
        var j: usize = 0;
        while (j < 17) : (j += 1) {
            if ((j % 3) == 2) {
                if (text[i + j] != sep) {
                    ok = false;
                    break;
                }
                out[j] = ':';
            } else {
                const c = text[i + j];
                if (!isHexAscii(c)) {
                    ok = false;
                    break;
                }
                out[j] = std.ascii.toLower(c);
            }
        }

        if (ok) return out;
    }

    return null;
}

fn isHexAscii(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn normalizeOuiPrefix(input: []const u8, out: *[6]u8) bool {
    var idx: usize = 0;
    for (input) |c| {
        if (!isHexAscii(c)) continue;
        out[idx] = std.ascii.toUpper(c);
        idx += 1;
        if (idx == out.len) return true;
    }
    return false;
}

fn inferDeviceType(services: []const ServiceInfo, insight: HostInsight, l2_info: HostLayer2Info) InferenceResult {
    var printer_score: i32 = 0;
    var server_score: i32 = 0;
    var nas_score: i32 = 0;
    var network_score: i32 = 0;
    var iot_score: i32 = 0;

    for (services) |svc| {
        switch (svc.port) {
            515, 631, 9100, 1865 => printer_score += 3,
            139, 445 => {
                printer_score += 1;
                nas_score += 2;
            },
            2049, 111 => nas_score += 3,
            22, 80, 443, 3389, 5985, 5986 => server_score += 1,
            23, 161, 162, 1900 => network_score += 2,
            1883, 8883, 5683 => iot_score += 3,
            else => {},
        }

        if (hasPrinterSignal(svc.banner) or hasPrinterSignal(svc.details)) printer_score += 5;
        if (hasNasSignal(svc.banner) or hasNasSignal(svc.details)) nas_score += 5;
        if (hasNetworkSignal(svc.banner) or hasNetworkSignal(svc.details)) network_score += 4;
        if (hasServerSignal(svc.banner) or hasServerSignal(svc.details)) server_score += 3;
        if (hasIotSignal(svc.banner) or hasIotSignal(svc.details)) iot_score += 3;
    }

    if (l2_info.found) {
        if (containsAnyIgnoreCase(l2_info.vendor, &.{
            "hewlett",
            "hp",
            "brother",
            "epson",
            "canon",
            "xerox",
            "lexmark",
            "ricoh",
            "kyocera",
            "konica",
        })) {
            printer_score += 7;
        }
        if (containsAnyIgnoreCase(l2_info.vendor, &.{
            "synology",
            "qnap",
            "asustor",
            "netapp",
            "drobo",
        })) {
            nas_score += 7;
        }
        if (containsAnyIgnoreCase(l2_info.vendor, &.{
            "cisco",
            "ubiquiti",
            "juniper",
            "aruba",
            "fortinet",
            "mikrotik",
            "palo alto",
            "tp-link",
            "netgear",
        })) {
            network_score += 6;
        }
        if (containsAnyIgnoreCase(l2_info.vendor, &.{
            "raspberry",
            "espressif",
            "tuya",
            "sonoff",
        })) {
            iot_score += 6;
        }
    }

    if (insight.print_stack >= 2) printer_score += 5;
    if (insight.remote_access > 0) server_score += 2;
    if (insight.data_store >= 2 or (insight.data_store > 0 and insight.file_share > 0)) nas_score += 3;
    if (insight.web > 0 and insight.remote_access == 0 and insight.data_store == 0 and insight.print_stack == 0) {
        iot_score += 2;
    }
    if (services.len > 0 and insight.known_services == 0 and insight.unknown_services >= 2) iot_score += 2;

    const best = selectBestDeviceType(printer_score, server_score, nas_score, network_score, iot_score);
    const second = selectSecondBestDeviceScore(best.kind, printer_score, server_score, nas_score, network_score, iot_score);
    const gap = best.score - second;

    if (best.score <= 0) {
        return .{
            .label = "Unknown",
            .confidence = .low,
            .reason = "insufficient device fingerprint data",
            .score = 0,
            .gap = 0,
        };
    }

    return .{
        .label = deviceTypeLabel(best.kind),
        .confidence = inferConfidence(best.score, gap),
        .reason = deviceReason(best.kind, insight, services),
        .score = best.score,
        .gap = gap,
    };
}

fn inferOs(
    services: []const ServiceInfo,
    insight: HostInsight,
    l2_info: HostLayer2Info,
    device_guess: InferenceResult,
) InferenceResult {
    var windows_score: i32 = 0;
    var linux_score: i32 = 0;
    var mac_score: i32 = 0;
    var appliance_score: i32 = 0;

    for (services) |svc| {
        switch (svc.port) {
            135 => windows_score += 4,
            139 => windows_score += 1,
            445 => windows_score += 2,
            3389, 5985, 5986 => windows_score += 5,
            22 => linux_score += 3,
            111 => linux_score += 3,
            2049 => linux_score += 4,
            873, 2375, 2376 => linux_score += 2,
            548, 62078 => mac_score += 4,
            23, 161, 162, 1900 => appliance_score += 2,
            515, 631, 9100, 1865 => appliance_score += 3,
            else => {},
        }

        if (hasWindowsSignal(svc.banner) or hasWindowsSignal(svc.details)) windows_score += 4;
        if (hasLinuxSignal(svc.banner) or hasLinuxSignal(svc.details)) linux_score += 3;
        if (hasMacSignal(svc.banner) or hasMacSignal(svc.details)) mac_score += 4;
        if (hasApplianceSignal(svc.banner) or hasApplianceSignal(svc.details)) appliance_score += 4;
    }

    if (l2_info.found) {
        if (containsAnyIgnoreCase(l2_info.vendor, &.{"apple"})) mac_score += 6;
        if (containsAnyIgnoreCase(l2_info.vendor, &.{"microsoft"})) windows_score += 5;
        if (containsAnyIgnoreCase(l2_info.vendor, &.{
            "hewlett",
            "hp",
            "brother",
            "epson",
            "canon",
            "xerox",
            "lexmark",
            "ricoh",
            "kyocera",
            "konica",
        })) {
            appliance_score += 5;
        }
        if (containsAnyIgnoreCase(l2_info.vendor, &.{
            "cisco",
            "ubiquiti",
            "juniper",
            "aruba",
            "fortinet",
            "mikrotik",
            "tp-link",
            "netgear",
        })) {
            appliance_score += 4;
        }
    }

    if (insight.print_stack >= 2) appliance_score += 6;
    if (insight.remote_access > 0 and insight.print_stack == 0) {
        windows_score += 1;
        linux_score += 1;
    }
    if (insight.data_store >= 1 and insight.file_share >= 1) linux_score += 2;
    if (insight.print_stack >= 2 and insight.remote_access == 0 and windows_score > 0) windows_score -= 2;

    if (std.mem.eql(u8, device_guess.label, "Printer / MFP")) appliance_score += 6;
    if (std.mem.eql(u8, device_guess.label, "Network Appliance")) appliance_score += 3;
    if (std.mem.eql(u8, device_guess.label, "NAS / Storage")) linux_score += 3;

    const best = selectBestOsFamily(windows_score, linux_score, mac_score, appliance_score);
    const second = selectSecondBestOsScore(best.kind, windows_score, linux_score, mac_score, appliance_score);
    const gap = best.score - second;

    if (best.score <= 0) {
        return .{
            .label = "Unknown",
            .confidence = .low,
            .reason = "insufficient OS fingerprint data",
            .score = 0,
            .gap = 0,
        };
    }

    return .{
        .label = osFamilyLabel(best.kind),
        .confidence = inferConfidence(best.score, gap),
        .reason = osReason(best.kind, insight, services, device_guess),
        .score = best.score,
        .gap = gap,
    };
}

fn inferConfidence(score: i32, gap: i32) InferenceConfidence {
    if (score >= 12 and gap >= 5) return .high;
    if (score >= 7 and gap >= 2) return .medium;
    return .low;
}

fn selectBestDeviceType(
    printer_score: i32,
    server_score: i32,
    nas_score: i32,
    network_score: i32,
    iot_score: i32,
) DeviceScore {
    var best = DeviceScore{ .kind = .printer_mfp, .score = printer_score };
    const candidates = [_]DeviceScore{
        .{ .kind = .server_workstation, .score = server_score },
        .{ .kind = .nas_storage, .score = nas_score },
        .{ .kind = .network_appliance, .score = network_score },
        .{ .kind = .iot_embedded, .score = iot_score },
    };

    for (candidates) |candidate| {
        if (candidate.score > best.score) best = candidate;
    }
    return best;
}

fn selectSecondBestDeviceScore(
    best_kind: DeviceType,
    printer_score: i32,
    server_score: i32,
    nas_score: i32,
    network_score: i32,
    iot_score: i32,
) i32 {
    const scores = [_]DeviceScore{
        .{ .kind = .printer_mfp, .score = printer_score },
        .{ .kind = .server_workstation, .score = server_score },
        .{ .kind = .nas_storage, .score = nas_score },
        .{ .kind = .network_appliance, .score = network_score },
        .{ .kind = .iot_embedded, .score = iot_score },
    };

    var second: i32 = std.math.minInt(i32);
    for (scores) |entry| {
        if (entry.kind == best_kind) continue;
        if (entry.score > second) second = entry.score;
    }
    return second;
}

fn selectBestOsFamily(
    windows_score: i32,
    linux_score: i32,
    mac_score: i32,
    appliance_score: i32,
) OsScore {
    var best = OsScore{ .kind = .windows, .score = windows_score };
    const candidates = [_]OsScore{
        .{ .kind = .linux_unix, .score = linux_score },
        .{ .kind = .macos_apple, .score = mac_score },
        .{ .kind = .appliance_embedded, .score = appliance_score },
    };

    for (candidates) |candidate| {
        if (candidate.score > best.score) best = candidate;
    }
    return best;
}

fn selectSecondBestOsScore(
    best_kind: OsFamily,
    windows_score: i32,
    linux_score: i32,
    mac_score: i32,
    appliance_score: i32,
) i32 {
    const scores = [_]OsScore{
        .{ .kind = .windows, .score = windows_score },
        .{ .kind = .linux_unix, .score = linux_score },
        .{ .kind = .macos_apple, .score = mac_score },
        .{ .kind = .appliance_embedded, .score = appliance_score },
    };

    var second: i32 = std.math.minInt(i32);
    for (scores) |entry| {
        if (entry.kind == best_kind) continue;
        if (entry.score > second) second = entry.score;
    }
    return second;
}

fn deviceTypeLabel(kind: DeviceType) []const u8 {
    return switch (kind) {
        .printer_mfp => "Printer / MFP",
        .server_workstation => "Server / Workstation",
        .nas_storage => "NAS / Storage",
        .network_appliance => "Network Appliance",
        .iot_embedded => "IoT / Embedded",
        .unknown => "Unknown",
    };
}

fn osFamilyLabel(kind: OsFamily) []const u8 {
    return switch (kind) {
        .windows => "Windows",
        .linux_unix => "Linux / Unix",
        .macos_apple => "macOS / Apple",
        .appliance_embedded => "Embedded / Appliance",
        .unknown => "Unknown",
    };
}

fn deviceReason(kind: DeviceType, insight: HostInsight, services: []const ServiceInfo) []const u8 {
    _ = services;
    return switch (kind) {
        .printer_mfp => if (insight.print_stack >= 2)
            "multiple print stack protocols exposed"
        else
            "printer vendor/protocol fingerprints present",
        .server_workstation => if (insight.remote_access > 0)
            "remote administration ports are exposed"
        else
            "general-purpose service mix matches host/server",
        .nas_storage => if (insight.file_share > 0 and insight.data_store > 0)
            "file share + datastore service combination detected"
        else
            "network storage protocol fingerprints present",
        .network_appliance => "network management protocol fingerprints present",
        .iot_embedded => "lightweight embedded service footprint detected",
        .unknown => "insufficient device fingerprint data",
    };
}

fn osReason(kind: OsFamily, insight: HostInsight, services: []const ServiceInfo, device_guess: InferenceResult) []const u8 {
    _ = services;
    return switch (kind) {
        .windows => if (insight.remote_access > 0)
            "Windows-native management services scored highest"
        else
            "SMB/Microsoft fingerprints dominate",
        .linux_unix => if (insight.data_store > 0 and insight.file_share > 0)
            "Unix-style storage/service mix scored highest"
        else
            "Linux/Unix banner fingerprints dominate",
        .macos_apple => "Apple-specific service fingerprints detected",
        .appliance_embedded => if (std.mem.eql(u8, device_guess.label, "Printer / MFP"))
            "printer profile strongly indicates embedded firmware"
        else
            "appliance/embedded network signatures dominate",
        .unknown => "insufficient OS fingerprint data",
    };
}

fn hasWindowsSignal(text: []const u8) bool {
    return containsAnyIgnoreCase(text, &.{
        "windows",
        "microsoft",
        "winrm",
        "iis",
        "msrpc",
        "smb",
        "ntlm",
    });
}

fn hasLinuxSignal(text: []const u8) bool {
    return containsAnyIgnoreCase(text, &.{
        "linux",
        "ubuntu",
        "debian",
        "centos",
        "fedora",
        "opensuse",
        "freebsd",
        "openbsd",
        "openssh",
        "nginx",
        "apache",
    });
}

fn hasMacSignal(text: []const u8) bool {
    return containsAnyIgnoreCase(text, &.{
        "mac os",
        "macos",
        "darwin",
        "bonjour",
        "airprint",
        "apple",
    });
}

fn hasPrinterSignal(text: []const u8) bool {
    return containsAnyIgnoreCase(text, &.{
        "printer",
        "jetdirect",
        "@pjl",
        "airprint",
        "ipp",
        "hp",
        "hewlett",
        "brother",
        "epson",
        "canon",
        "xerox",
        "lexmark",
        "ricoh",
        "kyocera",
        "konica",
    });
}

fn hasNasSignal(text: []const u8) bool {
    return containsAnyIgnoreCase(text, &.{
        "synology",
        "qnap",
        "truenas",
        "openmediavault",
        "samba",
        "nfs",
        "iscsi",
        "netapp",
    });
}

fn hasNetworkSignal(text: []const u8) bool {
    return containsAnyIgnoreCase(text, &.{
        "cisco",
        "routeros",
        "mikrotik",
        "openwrt",
        "ubiquiti",
        "ubnt",
        "fortinet",
        "sonicwall",
        "pfsense",
        "tplink",
        "netgear",
    });
}

fn hasIotSignal(text: []const u8) bool {
    return containsAnyIgnoreCase(text, &.{
        "busybox",
        "mqtt",
        "esp",
        "iot",
        "smart",
    });
}

fn hasServerSignal(text: []const u8) bool {
    return containsAnyIgnoreCase(text, &.{
        "server",
        "postgres",
        "mysql",
        "mongodb",
        "kafka",
        "docker",
    });
}

fn hasApplianceSignal(text: []const u8) bool {
    return hasPrinterSignal(text) or hasNetworkSignal(text) or containsAnyIgnoreCase(text, &.{
        "embedded",
        "firmware",
    });
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) break;
        }
        if (j == needle.len) return true;
    }
    return false;
}

fn containsAnyIgnoreCase(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (containsIgnoreCase(haystack, needle)) return true;
    }
    return false;
}

fn parsePortRange(raw: []const u8) !PortRange {
    if (std.mem.eql(u8, raw, "all")) {
        return .{ .start = 1, .end = 65535 };
    }

    if (std.mem.indexOfScalar(u8, raw, '-')) |dash_idx| {
        const left = std.mem.trim(u8, raw[0..dash_idx], " ");
        const right = std.mem.trim(u8, raw[dash_idx + 1 ..], " ");
        if (left.len == 0 or right.len == 0) return error.InvalidPortRange;

        const start = try std.fmt.parseUnsigned(u16, left, 10);
        const end = try std.fmt.parseUnsigned(u16, right, 10);

        if (start == 0 or end == 0 or start > end) return error.InvalidPortRange;
        return .{ .start = start, .end = end };
    }

    const single = try std.fmt.parseUnsigned(u16, raw, 10);
    if (single == 0) return error.InvalidPortRange;
    return .{ .start = single, .end = single };
}

fn resolveColor(mode: ColorMode, stdout_supports_color: bool) bool {
    return switch (mode) {
        .auto => stdout_supports_color,
        .always => true,
        .never => false,
    };
}

fn printScanPreamble(out: anytype, style: UiStyle, config: ScanConfig, candidate_count: usize) !void {
    try out.print("{s}\n", .{hr_heavy});
    try out.print(
        "{s}{s}ZIGMAP :: LOCAL NETWORK SCAN{s}\n",
        .{ style.esc(Ansi.bold), style.esc(Ansi.cyan), style.esc(Ansi.reset) },
    );
    try out.print("{s}\n", .{hr_heavy});
    try out.print("Target CIDR        : {s}\n", .{config.cidr});
    try out.print("Candidate Hosts    : {d}\n", .{candidate_count});
    try out.print("Scan Ports         : {d}-{d} ({d} ports)\n", .{
        config.ports.start,
        config.ports.end,
        config.ports.count(),
    });
    try out.print("Workers / Timeout  : {d} / {d} ms\n", .{ config.workers, config.timeout_ms });
    try out.print("Discovery Ports    : ", .{});
    try printPortPreview(out, config.discovery_ports, 20);
    try out.print("\n", .{});
    try out.print("{s}\n", .{hr_light});
    try out.print(
        "{s}Phase 1: Host discovery in progress...{s}\n",
        .{ style.esc(Ansi.blue), style.esc(Ansi.reset) },
    );
}

fn printDiscoverySummary(
    out: anytype,
    style: UiStyle,
    up_hosts: usize,
    candidate_hosts: usize,
    elapsed_ms: i64,
) !void {
    const ratio = if (candidate_hosts == 0)
        @as(f64, 0.0)
    else
        (@as(f64, @floatFromInt(up_hosts)) * 100.0) / @as(f64, @floatFromInt(candidate_hosts));
    const state_color = if (up_hosts > 0) Ansi.green else Ansi.yellow;

    try out.print(
        "{s}Discovery result{s}: {s}{d}/{d}{s} hosts up | {d:.1}% responsive | {d} ms\n",
        .{
            style.esc(Ansi.bold),
            style.esc(Ansi.reset),
            style.esc(state_color),
            up_hosts,
            candidate_hosts,
            style.esc(Ansi.reset),
            ratio,
            elapsed_ms,
        },
    );
    try out.print("{s}\n", .{hr_heavy});
}

fn printHostReport(
    out: anytype,
    style: UiStyle,
    host_index: usize,
    host_total: usize,
    ip_text: []const u8,
    open_ports: []const u16,
    services: []const ServiceInfo,
    insight: HostInsight,
    l2_info: HostLayer2Info,
    device_guess: InferenceResult,
    os_guess: InferenceResult,
    elapsed_ms: i64,
) !void {
    const open_color = if (open_ports.len == 0)
        Ansi.dim
    else if (open_ports.len <= 4)
        Ansi.green
    else if (open_ports.len <= 15)
        Ansi.yellow
    else
        Ansi.red;

    try out.print("\n{s}\n", .{hr_light});
    try out.print(
        "{s}{s}HOST {d}/{d} :: {s}{s}\n",
        .{
            style.esc(Ansi.bold),
            style.esc(Ansi.cyan),
            host_index,
            host_total,
            ip_text,
            style.esc(Ansi.reset),
        },
    );
    try out.print("{s}\n", .{hr_light});
    try out.print("Scan Time          : {d} ms\n", .{elapsed_ms});
    try out.print(
        "Open TCP Ports     : {s}{d}{s} (known: {d}, unknown: {d}, banners: {d})\n",
        .{
            style.esc(open_color),
            open_ports.len,
            style.esc(Ansi.reset),
            insight.known_services,
            insight.unknown_services,
            insight.banners,
        },
    );
    try out.print("Host Profile       : ", .{});
    try printHostProfile(out, insight);
    try out.print("\n", .{});
    try out.print("Layer2 Identity    : ", .{});
    try printLayer2Identity(out, l2_info);
    try out.print("\n", .{});
    try out.print("Device Class       : ", .{});
    try printInference(out, style, device_guess, .device);
    try out.print("\n", .{});
    try out.print("OS Guess           : ", .{});
    try printInference(out, style, os_guess, .os);
    try out.print("\n", .{});
    try out.print("Port Set           : ", .{});
    try printPortPreview(out, open_ports, 28);
    try out.print("\n", .{});

    if (services.len == 0) {
        try out.print("Services           : none\n", .{});
        return;
    }

    try out.print("Services ({d})\n", .{services.len});
    try out.print("  {s: >5}  {s: <18}  {s: <8}  {s: <11}  {s}\n", .{
        "PORT",
        "SERVICE",
        "CONF",
        "METHOD",
        "DETAILS",
    });

    for (services) |svc| {
        const confidence = serviceConfidence(svc);
        try out.print("  {d: >5}  {s: <18}  ", .{ svc.port, svc.name });
        try printConfidence(out, style, confidence);
        try out.print("  {s: <11}  ", .{serviceMethodLabel(svc.quality)});
        const detail = if (svc.details.len > 0) svc.details else svc.banner;
        try printBannerPreview(out, detail, 96);
        try out.print("\n", .{});
    }
}

fn printFinalSummary(
    out: anytype,
    style: UiStyle,
    live_hosts: usize,
    candidate_hosts: usize,
    total_open_ports: usize,
    hosts_with_unknown: usize,
    uncertain_os_hosts: usize,
    elapsed_ms: i64,
) !void {
    const avg_ports = if (live_hosts == 0)
        @as(f64, 0.0)
    else
        @as(f64, @floatFromInt(total_open_ports)) / @as(f64, @floatFromInt(live_hosts));

    try out.print("\n{s}\n", .{hr_heavy});
    try out.print(
        "{s}{s}SCAN SUMMARY{s}\n",
        .{ style.esc(Ansi.bold), style.esc(Ansi.magenta), style.esc(Ansi.reset) },
    );
    try out.print("{s}\n", .{hr_heavy});
    try out.print("Live Hosts         : {d}/{d}\n", .{ live_hosts, candidate_hosts });
    try out.print("Total Open Ports   : {d}\n", .{total_open_ports});
    try out.print("Avg Ports / Host   : {d:.2}\n", .{avg_ports});
    try out.print("Hosts w/ Unknowns  : {d}\n", .{hosts_with_unknown});
    try out.print("Uncertain OS Guess : {d}\n", .{uncertain_os_hosts});
    try out.print("Total Duration     : {d} ms\n", .{elapsed_ms});
    try out.print("{s}\n", .{hr_heavy});
}

fn printPortPreview(out: anytype, ports: []const u16, max_show: usize) !void {
    if (ports.len == 0) {
        try out.print("-", .{});
        return;
    }

    const shown = @min(ports.len, max_show);
    for (ports[0..shown], 0..) |port, idx| {
        if (idx != 0) try out.print(", ", .{});
        try out.print("{d}", .{port});
    }
    if (ports.len > shown) {
        try out.print(", +{d} more", .{ports.len - shown});
    }
}

fn analyzeHost(services: []const ServiceInfo) HostInsight {
    var insight = HostInsight{};

    for (services) |svc| {
        if (std.mem.eql(u8, svc.name, "unknown")) {
            insight.unknown_services += 1;
        } else {
            insight.known_services += 1;
        }
        if (svc.banner.len > 0) insight.banners += 1;
        if (isWebPort(svc.port)) insight.web += 1;
        if (isFileSharePort(svc.port)) insight.file_share += 1;
        if (isPrintPort(svc.port)) insight.print_stack += 1;
        if (isRemotePort(svc.port)) insight.remote_access += 1;
        if (isDataStorePort(svc.port)) insight.data_store += 1;
    }

    return insight;
}

fn printLayer2Identity(out: anytype, l2_info: HostLayer2Info) !void {
    if (!l2_info.found) {
        try out.print("unresolved", .{});
        return;
    }
    try out.print("{s} ({s}, via {s})", .{
        l2_info.macSlice(),
        l2_info.vendor,
        l2_info.source,
    });
}

fn printHostProfile(out: anytype, insight: HostInsight) !void {
    var wrote_any = false;

    if (insight.web > 0) {
        try out.print("web-ui", .{});
        wrote_any = true;
    }
    if (insight.file_share > 0) {
        if (wrote_any) try out.print(", ", .{});
        try out.print("file-share", .{});
        wrote_any = true;
    }
    if (insight.print_stack > 0) {
        if (wrote_any) try out.print(", ", .{});
        try out.print("print-stack", .{});
        wrote_any = true;
    }
    if (insight.remote_access > 0) {
        if (wrote_any) try out.print(", ", .{});
        try out.print("remote-access", .{});
        wrote_any = true;
    }
    if (insight.data_store > 0) {
        if (wrote_any) try out.print(", ", .{});
        try out.print("data-store", .{});
        wrote_any = true;
    }
    if (insight.unknown_services > 0 and insight.known_services == 0) {
        if (wrote_any) try out.print(", ", .{});
        try out.print("opaque", .{});
        wrote_any = true;
    }
    if (!wrote_any) {
        try out.print("generic", .{});
    }
}

const ServiceConfidence = enum(u8) {
    high,
    medium,
    low,
};

fn serviceConfidence(svc: ServiceInfo) ServiceConfidence {
    return switch (svc.quality) {
        .port_and_banner => .high,
        .banner_only => .medium,
        .port_only => .medium,
        .guessed => if (svc.banner.len > 0 or svc.details.len > 0) .medium else .low,
    };
}

fn printConfidence(out: anytype, style: UiStyle, confidence: ServiceConfidence) !void {
    const label = switch (confidence) {
        .high => "high",
        .medium => "medium",
        .low => "low",
    };
    const color = switch (confidence) {
        .high => Ansi.green,
        .medium => Ansi.yellow,
        .low => Ansi.dim,
    };

    try out.print(
        "{s}{s: <8}{s}",
        .{ style.esc(color), label, style.esc(Ansi.reset) },
    );
}

fn serviceMethodLabel(quality: ServiceMatchQuality) []const u8 {
    return switch (quality) {
        .port_and_banner => "port+banner",
        .banner_only => "banner",
        .port_only => "port-map",
        .guessed => "heuristic",
    };
}

fn printBannerPreview(out: anytype, banner: []const u8, max_len: usize) !void {
    if (banner.len == 0) {
        try out.print("-", .{});
        return;
    }

    if (banner.len <= max_len) {
        try out.print("{s}", .{banner});
        return;
    }

    const clipped_len = if (max_len > 3) max_len - 3 else max_len;
    try out.print("{s}...", .{banner[0..clipped_len]});
}

const InferenceKind = enum(u8) {
    os,
    device,
};

fn printInference(out: anytype, style: UiStyle, inference: InferenceResult, kind: InferenceKind) !void {
    const color = switch (inference.confidence) {
        .high => Ansi.green,
        .medium => Ansi.yellow,
        .low => Ansi.dim,
    };
    const conf = confidenceLabel(inference.confidence);
    const kind_prefix = switch (kind) {
        .os => "",
        .device => "",
    };

    try out.print(
        "{s}{s}{s}{s} ({s}, score={d}, gap={d}; {s})",
        .{
            style.esc(color),
            kind_prefix,
            inference.label,
            style.esc(Ansi.reset),
            conf,
            inference.score,
            inference.gap,
            inference.reason,
        },
    );
}

fn confidenceLabel(confidence: InferenceConfidence) []const u8 {
    return switch (confidence) {
        .high => "high",
        .medium => "medium",
        .low => "low",
    };
}

fn isWebPort(port: u16) bool {
    return switch (port) {
        80, 81, 443, 8000, 8006, 8080, 8081, 8443, 8888, 9000 => true,
        else => false,
    };
}

fn isFileSharePort(port: u16) bool {
    return switch (port) {
        139, 445, 2049 => true,
        else => false,
    };
}

fn isPrintPort(port: u16) bool {
    return switch (port) {
        515, 631, 9100 => true,
        else => false,
    };
}

fn isRemotePort(port: u16) bool {
    return switch (port) {
        22, 23, 3389, 5900, 5985, 5986 => true,
        else => false,
    };
}

fn isDataStorePort(port: u16) bool {
    return switch (port) {
        1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017 => true,
        else => false,
    };
}

fn printUsage(out: anytype) !void {
    try out.print(
        \\zigmap - slim local network mapper in Zig
        \\
        \\Usage:
        \\  zig build run -- --cidr 192.168.1.0/24 [options]
        \\  zig build run -- 192.168.1.0/24 [options]
        \\
        \\Options:
        \\  --cidr <ipv4/prefix>       Target IPv4 CIDR (required if positional not used)
        \\  --ports <start-end|all>    TCP ports to scan (default: all)
        \\  --workers <n>              Concurrency level (default: auto)
        \\  --timeout-ms <n>           Per-connection timeout in ms (default: 180)
        \\  --max-hosts <n>            Cap scanned hosts from CIDR (default: 65536)
        \\  --discovery-ports <list>   Comma-separated ports for host discovery
        \\  --color                    Force ANSI color output
        \\  --no-color                 Disable ANSI color output
        \\  -h, --help                 Show this help
        \\
        \\Examples:
        \\  zig build run -- --cidr 192.168.1.0/24
        \\  zig build run -- 10.0.0.0/24 --ports 1-1024 --workers 256 --color
        \\  zig build run -- 172.16.1.0/24 --discovery-ports 22,80,443,445
        \\
        \\Note:
        \\  Run only on networks you own or are explicitly authorized to test.
        \\
    , .{});
}

fn defaultWorkerCount() usize {
    const cpu = std.Thread.getCpuCount() catch 4;

    var workers = if (cpu > (std.math.maxInt(usize) / 32)) 512 else cpu * 32;
    if (workers < 16) workers = 16;
    if (workers > 512) workers = 512;
    return workers;
}

fn effectiveWorkerCount(configured: usize, jobs: usize) usize {
    if (jobs == 0) return 1;
    if (configured == 0) return 1;
    return @min(configured, jobs);
}

fn ipToU32(ip: [4]u8) u32 {
    return (@as(u32, ip[0]) << 24) |
        (@as(u32, ip[1]) << 16) |
        (@as(u32, ip[2]) << 8) |
        @as(u32, ip[3]);
}

fn u32ToIp(ip_u32: u32) [4]u8 {
    return .{
        @intCast((ip_u32 >> 24) & 0xFF),
        @intCast((ip_u32 >> 16) & 0xFF),
        @intCast((ip_u32 >> 8) & 0xFF),
        @intCast(ip_u32 & 0xFF),
    };
}

fn ipToString(ip: [4]u8, buf: *[16]u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
}

test "parsePortRange all and range" {
    const all = try parsePortRange("all");
    try std.testing.expectEqual(@as(u16, 1), all.start);
    try std.testing.expectEqual(@as(u16, 65535), all.end);

    const range = try parsePortRange("20-25");
    try std.testing.expectEqual(@as(u16, 20), range.start);
    try std.testing.expectEqual(@as(u16, 25), range.end);
}

test "containsIgnoreCase" {
    try std.testing.expect(containsIgnoreCase("OpenSSH_9.6", "openssh"));
    try std.testing.expect(!containsIgnoreCase("nginx", "apache"));
}

test "printer footprint inference prefers appliance over windows smb bias" {
    var empty = [_]u8{};
    const services = [_]ServiceInfo{
        .{ .port = 80, .name = "http", .banner = empty[0..], .details = empty[0..], .quality = .port_only },
        .{ .port = 139, .name = "netbios", .banner = empty[0..], .details = empty[0..], .quality = .port_only },
        .{ .port = 443, .name = "https", .banner = empty[0..], .details = empty[0..], .quality = .port_only },
        .{ .port = 445, .name = "microsoft-ds", .banner = empty[0..], .details = empty[0..], .quality = .port_only },
        .{ .port = 515, .name = "printer", .banner = empty[0..], .details = empty[0..], .quality = .port_only },
        .{ .port = 631, .name = "ipp", .banner = empty[0..], .details = empty[0..], .quality = .port_only },
        .{ .port = 1865, .name = "unknown", .banner = empty[0..], .details = empty[0..], .quality = .guessed },
        .{ .port = 9100, .name = "jetdirect", .banner = empty[0..], .details = empty[0..], .quality = .port_only },
    };

    const insight = analyzeHost(services[0..]);
    const l2_unknown = HostLayer2Info{};
    const device = inferDeviceType(services[0..], insight, l2_unknown);
    const os = inferOs(services[0..], insight, l2_unknown, device);

    try std.testing.expect(std.mem.eql(u8, device.label, "Printer / MFP"));
    try std.testing.expect(std.mem.eql(u8, os.label, "Embedded / Appliance"));
    try std.testing.expect(os.confidence != .low);
}

test "service fingerprint uses banner signatures" {
    var pjl_banner = [_]u8{ '@', 'P', 'J', 'L', ' ', 'I', 'N', 'F', 'O', ' ', 'I', 'D' };
    var tls_banner = [_]u8{ '[', 'T', 'L', 'S', ' ', 'b', 'i', 'n', 'a', 'r', 'y', ' ', 'r', 'e', 'c', 'o', 'r', 'd', ']' };

    const pjl_fp = fingerprintService(9100, pjl_banner[0..]);
    try std.testing.expect(std.mem.eql(u8, pjl_fp.name, "jetdirect"));
    try std.testing.expect(pjl_fp.quality == .port_and_banner);

    const tls_fp = fingerprintService(443, tls_banner[0..]);
    try std.testing.expect(!std.mem.eql(u8, tls_fp.name, "unknown"));
}

test "parse mac from arp-like output" {
    const sample = "? (192.168.0.200) at 1c:bf:ce:11:22:33 on en0 ifscope [ethernet]";
    const parsed = parseMacFromText(sample);
    try std.testing.expect(parsed != null);
    try std.testing.expect(std.mem.eql(u8, parsed.?[0..], "1c:bf:ce:11:22:33"));
}

test "http response metadata summary parsing" {
    const sample =
        "HTTP/1.1 200 OK\r\n" ++
        "Server: nginx/1.27\r\n" ++
        "Location: /admin\r\n" ++
        "\r\n" ++
        "<html><head><title>Device Console</title></head><body>ok</body></html>";

    const allocator = std.testing.allocator;
    const summary = try summarizeHttpResponse(allocator, sample);
    defer allocator.free(summary);

    try std.testing.expect(containsIgnoreCase(summary, "status=HTTP/1.1 200 OK"));
    try std.testing.expect(containsIgnoreCase(summary, "server=nginx/1.27"));
    try std.testing.expect(containsIgnoreCase(summary, "title=Device Console"));
}

test "mac vendor fallback lookup" {
    const allocator = std.testing.allocator;
    var db = MacVendorDb.init(allocator);
    defer db.deinit();

    const vendor = db.vendorForMac("08:00:27:12:34:56");
    try std.testing.expect(containsIgnoreCase(vendor, "virtualbox"));
}
