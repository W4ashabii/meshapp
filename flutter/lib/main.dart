import 'dart:ffi';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:ffi/ffi.dart';

// FFI bindings for Rust core library
class RustCore {
  static DynamicLibrary? _dylib;
  
  static DynamicLibrary get dylib {
    if (_dylib != null) return _dylib!;
    
    if (Platform.isAndroid) {
      _dylib = DynamicLibrary.open('libmeshapp_core.so');
    } else if (Platform.isIOS) {
      _dylib = DynamicLibrary.process();
    } else if (Platform.isLinux) {
      _dylib = DynamicLibrary.open('libmeshapp_core.so');
    } else if (Platform.isMacOS) {
      _dylib = DynamicLibrary.open('libmeshapp_core.dylib');
    } else if (Platform.isWindows) {
      _dylib = DynamicLibrary.open('meshapp_core.dll');
    } else {
      throw UnsupportedError('Platform not supported');
    }
    
    return _dylib!;
  }
  
  // FFI function signatures
  static final _testFfi = dylib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('test_ffi');
  
  static final _freeString = dylib.lookupFunction<
      Void Function(Pointer<Utf8>),
      void Function(Pointer<Utf8>)>('free_string');
  
  /// Test FFI connection
  static String testFfi() {
    try {
      final ptr = _testFfi();
      if (ptr == nullptr) {
        return 'Error: FFI returned null pointer';
      }
      final message = ptr.toDartString();
      _freeString(ptr);
      return message;
    } catch (e) {
      return 'Error: $e';
    }
  }
}

void main() {
  runApp(const MeshApp());
}

class MeshApp extends StatelessWidget {
  const MeshApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Mesh Messenger',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  String _ffiStatus = 'Not tested yet';
  bool _isLoading = false;

  void _testFfi() {
    setState(() {
      _isLoading = true;
    });

    try {
      final result = RustCore.testFfi();
      setState(() {
        _ffiStatus = result;
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _ffiStatus = 'Error: $e';
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text('Mesh Messenger'),
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Text(
                'Phase 0: FFI Skeleton',
                style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 32),
              const Text(
                'FFI Status:',
                style: TextStyle(fontSize: 18),
              ),
              const SizedBox(height: 8),
              Text(
                _ffiStatus,
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 16,
                  color: _ffiStatus.contains('Error')
                      ? Colors.red
                      : _ffiStatus.contains('successful')
                          ? Colors.green
                          : Colors.grey,
                ),
              ),
              const SizedBox(height: 32),
              ElevatedButton(
                onPressed: _isLoading ? null : _testFfi,
                child: _isLoading
                    ? const SizedBox(
                        width: 20,
                        height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Text('Test FFI Connection'),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

