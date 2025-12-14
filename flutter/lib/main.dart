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
      // For Linux desktop, try bundle lib directory first, then current directory
      final executablePath = Platform.resolvedExecutable;
      final executableDir = executablePath.substring(0, executablePath.lastIndexOf(Platform.pathSeparator));
      final bundleLibPath = '$executableDir${Platform.pathSeparator}lib${Platform.pathSeparator}libmeshapp_core.so';
      
      try {
        // Try bundle lib directory (for installed/bundled app)
        _dylib = DynamicLibrary.open(bundleLibPath);
      } catch (e) {
        try {
          // Fallback: try current directory (for development)
          _dylib = DynamicLibrary.open('libmeshapp_core.so');
        } catch (e2) {
          throw UnsupportedError('Could not load libmeshapp_core.so. Tried: $bundleLibPath and libmeshapp_core.so');
        }
      }
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
  
  static final _initIdentity = dylib.lookupFunction<
      Int32 Function(),
      int Function()>('init_identity');
  
  static final _getUserId = dylib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('get_user_id');
  
  static final _getFingerprint = dylib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('get_fingerprint');
  
  static final _getEd25519PublicKey = dylib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('get_ed25519_public_key');
  
  static final _getX25519PublicKey = dylib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('get_x25519_public_key');
  
  /// Helper to safely get a string from FFI
  static String? _getString(Pointer<Utf8> Function() getter) {
    try {
      final ptr = getter();
      if (ptr == nullptr) {
        return null;
      }
      final str = ptr.toDartString();
      _freeString(ptr);
      return str;
    } catch (e) {
      return null;
    }
  }
  
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
  
  /// Initialize identity (loads from storage or generates new)
  static bool initIdentity() {
    try {
      final result = _initIdentity();
      return result == 0;
    } catch (e) {
      return false;
    }
  }
  
  /// Get user ID (SHA256 of Ed25519 public key)
  static String? getUserId() => _getString(_getUserId);
  
  /// Get fingerprint (first 16 chars of user_id)
  static String? getFingerprint() => _getString(_getFingerprint);
  
  /// Get Ed25519 public key
  static String? getEd25519PublicKey() => _getString(_getEd25519PublicKey);
  
  /// Get X25519 public key
  static String? getX25519PublicKey() => _getString(_getX25519PublicKey);
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
  String? _userId;
  String? _fingerprint;
  String? _ed25519Key;
  String? _x25519Key;
  bool _isLoading = false;
  bool _identityInitialized = false;

  @override
  void initState() {
    super.initState();
    _initializeIdentity();
  }

  void _initializeIdentity() {
    setState(() {
      _isLoading = true;
    });

    try {
      if (RustCore.initIdentity()) {
        setState(() {
          _identityInitialized = true;
          _userId = RustCore.getUserId();
          _fingerprint = RustCore.getFingerprint();
          _ed25519Key = RustCore.getEd25519PublicKey();
          _x25519Key = RustCore.getX25519PublicKey();
          _isLoading = false;
        });
      } else {
        setState(() {
          _isLoading = false;
        });
      }
    } catch (e) {
      setState(() {
        _isLoading = false;
      });
    }
  }

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
          child: SingleChildScrollView(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Text(
                  'Phase 1: Identity',
                  style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 32),
                if (_isLoading)
                  const CircularProgressIndicator()
                else if (_identityInitialized) ...[
                  _buildIdentityCard('Fingerprint', _fingerprint ?? 'N/A', Icons.fingerprint),
                  const SizedBox(height: 16),
                  _buildIdentityCard('User ID', _userId ?? 'N/A', Icons.person),
                  const SizedBox(height: 16),
                  _buildIdentityCard('Ed25519 Public Key', _ed25519Key ?? 'N/A', Icons.vpn_key),
                  const SizedBox(height: 16),
                  _buildIdentityCard('X25519 Public Key', _x25519Key ?? 'N/A', Icons.vpn_key),
                  const SizedBox(height: 32),
                  ElevatedButton(
                    onPressed: _testFfi,
                    child: const Text('Test FFI Connection'),
                  ),
                  if (_ffiStatus != 'Not tested yet') ...[
                    const SizedBox(height: 16),
                    Text(
                      _ffiStatus,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 14,
                        color: _ffiStatus.contains('Error')
                            ? Colors.red
                            : Colors.green,
                      ),
                    ),
                  ],
                ] else ...[
                  const Text(
                    'Failed to initialize identity',
                    style: TextStyle(color: Colors.red),
                  ),
                  const SizedBox(height: 16),
                  ElevatedButton(
                    onPressed: _initializeIdentity,
                    child: const Text('Retry'),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildIdentityCard(String label, String value, IconData icon) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(icon, size: 20),
                const SizedBox(width: 8),
                Text(
                  label,
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            SelectableText(
              value,
              style: const TextStyle(
                fontSize: 12,
                fontFamily: 'monospace',
              ),
            ),
          ],
        ),
      ),
    );
  }
}

