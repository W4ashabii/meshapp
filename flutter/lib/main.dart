import 'dart:ffi';
import 'dart:io';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:ffi/ffi.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

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
  
  // Friends management FFI functions
  static final _initFriends = dylib.lookupFunction<
      Int32 Function(),
      int Function()>('init_friends');
  
  static final _addFriend = dylib.lookupFunction<
      Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
      Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('add_friend');
  
  static final _removeFriend = dylib.lookupFunction<
      Int32 Function(Pointer<Utf8>),
      int Function(Pointer<Utf8>)>('remove_friend');
  
  static final _getAllFriends = dylib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('get_all_friends');
  
  static final _exportOwnIdentity = dylib.lookupFunction<
      Pointer<Utf8> Function(),
      Pointer<Utf8> Function()>('export_own_identity');
  
  static final _importFriendFromJson = dylib.lookupFunction<
      Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
      Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('import_friend_from_json');
  
  /// Initialize friends manager
  static bool initFriends() {
    try {
      final result = _initFriends();
      if (result != 0) {
        print('init_friends returned: $result (expected 0)');
      }
      return result == 0;
    } catch (e) {
      print('Error calling init_friends: $e');
      return false;
    }
  }
  
  /// Add a friend
  static String? addFriend(String ed25519PublicHex, String nickname) {
    try {
      final publicKeyPtr = ed25519PublicHex.toNativeUtf8();
      final nicknamePtr = nickname.toNativeUtf8();
      
      final result = _addFriend(publicKeyPtr, nicknamePtr);
      
      malloc.free(publicKeyPtr);
      malloc.free(nicknamePtr);
      
      if (result == nullptr) {
        return null;
      }
      
      final userId = result.toDartString();
      _freeString(result);
      return userId;
    } catch (e) {
      return null;
    }
  }
  
  /// Remove a friend
  static bool removeFriend(String userIdHex) {
    try {
      final userIdPtr = userIdHex.toNativeUtf8();
      final result = _removeFriend(userIdPtr);
      malloc.free(userIdPtr);
      return result == 1;
    } catch (e) {
      return false;
    }
  }
  
  /// Get all friends as JSON
  static String? getAllFriends() => _getString(_getAllFriends);
  
  /// Export own identity for QR code
  static String? exportOwnIdentity() => _getString(_exportOwnIdentity);
  
  /// Import friend from JSON (QR scan)
  static String? importFriendFromJson(String json, String nickname) {
    try {
      final jsonPtr = json.toNativeUtf8();
      final nicknamePtr = nickname.toNativeUtf8();
      
      final result = _importFriendFromJson(jsonPtr, nicknamePtr);
      
      malloc.free(jsonPtr);
      malloc.free(nicknamePtr);
      
      if (result == nullptr) {
        return null;
      }
      
      final userId = result.toDartString();
      _freeString(result);
      return userId;
    } catch (e) {
      return null;
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

class _HomePageState extends State<HomePage> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  String? _userId;
  String? _fingerprint;
  String? _ed25519Key;
  String? _x25519Key;
  bool _isLoading = false;
  bool _identityInitialized = false;
  bool _friendsInitialized = false;
  List<Map<String, dynamic>> _friends = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _initialize();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  void _initialize() {
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
        });
      }

      final friendsInitResult = RustCore.initFriends();
      if (friendsInitResult) {
        setState(() {
          _friendsInitialized = true;
        });
        _loadFriends();
      } else {
        print('Failed to initialize friends - check console for details');
      }

      setState(() {
        _isLoading = false;
      });
    } catch (e) {
      setState(() {
        _isLoading = false;
      });
    }
  }

  void _loadFriends() {
    final friendsJson = RustCore.getAllFriends();
    if (friendsJson != null) {
      try {
        final List<dynamic> friendsList = jsonDecode(friendsJson);
        setState(() {
          _friends = friendsList.map((f) => f as Map<String, dynamic>).toList();
        });
      } catch (e) {
        // Error parsing friends
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text('Mesh Messenger'),
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(icon: Icon(Icons.person), text: 'Identity'),
            Tab(icon: Icon(Icons.people), text: 'Friends'),
          ],
        ),
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : TabBarView(
              controller: _tabController,
              children: [
                _buildIdentityTab(),
                _buildFriendsTab(),
              ],
            ),
    );
  }

  Widget _buildIdentityTab() {
    if (!_identityInitialized) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text('Failed to initialize identity', style: TextStyle(color: Colors.red)),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: _initialize,
              child: const Text('Retry'),
            ),
          ],
        ),
      );
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        children: [
          const Text(
            'Phase 2: Identity & Friends',
            style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 32),
          _buildIdentityCard('Fingerprint', _fingerprint ?? 'N/A', Icons.fingerprint),
          const SizedBox(height: 16),
          _buildIdentityCard('User ID', _userId ?? 'N/A', Icons.person),
          const SizedBox(height: 16),
          _buildIdentityCard('Ed25519 Public Key', _ed25519Key ?? 'N/A', Icons.vpn_key),
          const SizedBox(height: 16),
          _buildIdentityCard('X25519 Public Key', _x25519Key ?? 'N/A', Icons.vpn_key),
        ],
      ),
    );
  }

  Widget _buildFriendsTab() {
    if (!_friendsInitialized) {
      return const Center(child: Text('Failed to initialize friends'));
    }

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(16.0),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              ElevatedButton.icon(
                onPressed: () => _showQRExport(context),
                icon: const Icon(Icons.qr_code),
                label: const Text('Export QR'),
              ),
              ElevatedButton.icon(
                onPressed: () => _showQRScanner(context),
                icon: const Icon(Icons.qr_code_scanner),
                label: const Text('Scan QR'),
              ),
              ElevatedButton.icon(
                onPressed: () => _showAddFriendDialog(context),
                icon: const Icon(Icons.person_add),
                label: const Text('Add Friend'),
              ),
            ],
          ),
        ),
        Expanded(
          child: _friends.isEmpty
              ? const Center(
                  child: Text('No friends yet. Add one by scanning a QR code!'),
                )
              : ListView.builder(
                  itemCount: _friends.length,
                  itemBuilder: (context, index) {
                    final friend = _friends[index];
                    return Card(
                      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                      child: ListTile(
                        leading: const Icon(Icons.person),
                        title: Text(friend['nickname'] ?? 'Unknown'),
                        subtitle: Text(
                          friend['user_id']?.toString().substring(0, 16) ?? '',
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                        ),
                        trailing: IconButton(
                          icon: const Icon(Icons.delete),
                          onPressed: () => _removeFriend(friend['user_id']),
                        ),
                      ),
                    );
                  },
                ),
        ),
      ],
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

  void _showQRExport(BuildContext context) {
    final identityJson = RustCore.exportOwnIdentity();
    if (identityJson == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to export identity')),
      );
      return;
    }

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Your QR Code'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            QrImageView(
              data: identityJson,
              size: 200,
            ),
            const SizedBox(height: 16),
            SelectableText(
              identityJson,
              style: const TextStyle(fontSize: 10, fontFamily: 'monospace'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  void _showQRScanner(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => Dialog(
        child: Container(
          width: 300,
          height: 300,
          child: MobileScanner(
            onDetect: (capture) {
              final List<Barcode> barcodes = capture.barcodes;
              if (barcodes.isNotEmpty) {
                final barcode = barcodes.first;
                if (barcode.rawValue != null) {
                  Navigator.pop(context);
                  _importFriendFromQR(barcode.rawValue!);
                }
              }
            },
          ),
        ),
      ),
    );
  }

  void _importFriendFromQR(String qrData) {
    showDialog(
      context: context,
      builder: (context) {
        final nicknameController = TextEditingController();
        return AlertDialog(
          title: const Text('Add Friend'),
          content: TextField(
            controller: nicknameController,
            decoration: const InputDecoration(
              labelText: 'Nickname',
              hintText: 'Enter a nickname for this friend',
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Cancel'),
            ),
            TextButton(
              onPressed: () {
                final nickname = nicknameController.text.trim();
                if (nickname.isEmpty) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Please enter a nickname')),
                  );
                  return;
                }

                final userId = RustCore.importFriendFromJson(qrData, nickname);
                Navigator.pop(context);
                if (userId != null) {
                  _loadFriends();
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Friend added successfully!')),
                  );
                } else {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Failed to add friend')),
                  );
                }
              },
              child: const Text('Add'),
            ),
          ],
        );
      },
    );
  }

  void _showAddFriendDialog(BuildContext context) {
    final publicKeyController = TextEditingController();
    final nicknameController = TextEditingController();

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Add Friend Manually'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: publicKeyController,
              decoration: const InputDecoration(
                labelText: 'Ed25519 Public Key (hex)',
                hintText: 'Enter 64 hex characters',
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: nicknameController,
              decoration: const InputDecoration(
                labelText: 'Nickname',
                hintText: 'Enter a nickname',
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              final publicKey = publicKeyController.text.trim();
              final nickname = nicknameController.text.trim();
              if (publicKey.isEmpty || nickname.isEmpty) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Please fill all fields')),
                );
                return;
              }

              final userId = RustCore.addFriend(publicKey, nickname);
              Navigator.pop(context);
              if (userId != null) {
                _loadFriends();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Friend added successfully!')),
                );
              } else {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Failed to add friend')),
                );
              }
            },
            child: const Text('Add'),
          ),
        ],
      ),
    );
  }

  void _removeFriend(String userId) {
    if (RustCore.removeFriend(userId)) {
      _loadFriends();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Friend removed')),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to remove friend')),
      );
    }
  }
}

