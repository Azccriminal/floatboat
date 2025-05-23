import 'dart:async';
import 'dart:io';

typedef ItDefineTrigger = void Function(String message);

class ProcessInfo {
  final int pid;
  final String command;

  ProcessInfo(this.pid, this.command);
}

class HfsHunter {
  final List<String> forbiddenPatterns;
  final Duration scanInterval;
  final ItDefineTrigger onViolation;

  HfsHunter({
    required this.forbiddenPatterns,
    required this.onViolation,
    this.scanInterval = const Duration(seconds: 5),
  });

  Future<void> startScan() async {
    while (true) {
      await Future.delayed(scanInterval);

      final processes = await _getProcesses();

      for (final process in processes) {
        for (final pattern in forbiddenPatterns) {
          if (process.command.toLowerCase().contains(pattern.toLowerCase())) {
            onViolation(
              '[HFS] Unauthorized process detected: PID=${process.pid}, CMD=${process.command}',
            );
            return; // İstersen devam et, istersen durdur
          }
        }
      }
    }
  }

  Future<List<ProcessInfo>> _getProcesses() async {
    if (Platform.isLinux || Platform.isMacOS) {
      return _getProcessesUnix();
    } else if (Platform.isWindows) {
      return _getProcessesWindows();
    } else {
      return [];
    }
  }

  Future<List<ProcessInfo>> _getProcessesUnix() async {
    final result = await Process.run('ps', ['-eo', 'pid,comm']);
    if (result.exitCode != 0) {
      return [];
    }

    final lines = (result.stdout as String).split('\n');
    final List<ProcessInfo> processes = [];

    for (var line in lines.skip(1)) {
      line = line.trim();
      if (line.isEmpty) continue;
      final parts = line.split(RegExp(r'\s+'));
      if (parts.length < 2) continue;
      final pid = int.tryParse(parts[0]);
      final cmd = parts.sublist(1).join(' ');
      if (pid != null) {
        processes.add(ProcessInfo(pid, cmd));
      }
    }
    return processes;
  }

  Future<List<ProcessInfo>> _getProcessesWindows() async {
    final result = await Process.run('tasklist', []);
    if (result.exitCode != 0) {
      return [];
    }

    final lines = (result.stdout as String).split('\n');
    final List<ProcessInfo> processes = [];

    for (var line in lines.skip(3)) {
      line = line.trim();
      if (line.isEmpty) continue;
      final parts = line.split(RegExp(r'\s+'));
      if (parts.length < 2) continue;
      final cmd = parts[0];
      final pid = int.tryParse(parts[1]);
      if (pid != null) {
        processes.add(ProcessInfo(pid, cmd));
      }
    }
    return processes;
  }
}

void main() async {
  void customItDefine(String msg) {
    print(msg);
    // Burada istediğin ceza, uyarı, loglama, durdurma vb. işlemi yapabilirsin.
  }

  final hunter = HfsHunter(
    forbiddenPatterns: ['gdb', 'frida', 'radare2'],
    onViolation: customItDefine,
    scanInterval: Duration(seconds: 10),
  );

  await hunter.startScan();
}
