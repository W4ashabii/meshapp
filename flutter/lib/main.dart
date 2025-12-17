import 'dart:ffi';
import 'dart:io';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:ffi/ffi.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:shared_preferences/shared_preferences.dart';

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
  
  static final _initStorage = dylib.lookupFunction<
      Int32 Function(),
      int Function()>('init_storage');
  
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
  
  /// Initialize storage
  static bool initStorage() {
    try {
      return _initStorage() == 0;
    } catch (e) {
      return false;
    }
  }
  
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
  
  // Profile update FFI functions
  static final _updateFriendNickname = dylib.lookupFunction<
      Int32 Function(Pointer<Utf8>, Pointer<Utf8>),
      int Function(Pointer<Utf8>, Pointer<Utf8>)>('update_friend_nickname');
  
  static final _updateFriendProfile = dylib.lookupFunction<
      Int32 Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>),
      int Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>)>('update_friend_profile');
  
  /// Update friend nickname
  static bool updateFriendNickname(String userIdHex, String nickname) {
    try {
      final userIdPtr = userIdHex.toNativeUtf8();
      final nicknamePtr = nickname.toNativeUtf8();
      
      final result = _updateFriendNickname(userIdPtr, nicknamePtr);
      
      malloc.free(userIdPtr);
      malloc.free(nicknamePtr);
      
      return result == 0;
    } catch (e) {
      return false;
    }
  }
  
  /// Update friend profile
  /// All parameters except userIdHex can be null to leave unchanged
  static bool updateFriendProfile({
    required String userIdHex,
    String? nickname,
    String? notes,
    List<String>? tags,
    String? customDisplayName, // null = no change, empty = clear
  }) {
    try {
      final userIdPtr = userIdHex.toNativeUtf8();
      final nicknamePtr = nickname?.toNativeUtf8() ?? nullptr;
      final notesPtr = notes?.toNativeUtf8() ?? nullptr;
      final tagsJson = tags != null ? jsonEncode(tags).toNativeUtf8() : nullptr;
      final customDisplayNamePtr = customDisplayName?.toNativeUtf8() ?? nullptr;
      
      final result = _updateFriendProfile(
        userIdPtr,
        nicknamePtr,
        notesPtr,
        tagsJson,
        customDisplayNamePtr,
      );
      
      malloc.free(userIdPtr);
      if (nicknamePtr != nullptr) malloc.free(nicknamePtr);
      if (notesPtr != nullptr) malloc.free(notesPtr);
      if (tagsJson != nullptr) malloc.free(tagsJson);
      if (customDisplayNamePtr != nullptr) malloc.free(customDisplayNamePtr);
      
      return result == 0;
    } catch (e) {
      return false;
    }
  }
  
  // Messaging FFI functions
  static final _sendDmMessage = dylib.lookupFunction<
      Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>),
      Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>)>('send_dm_message');
  
  static final _getDmMessages = dylib.lookupFunction<
      Pointer<Utf8> Function(Pointer<Utf8>, Uint32, Uint32),
      Pointer<Utf8> Function(Pointer<Utf8>, int, int)>('get_dm_messages');
  
  static final _clearDmMessages = dylib.lookupFunction<
      Int32 Function(Pointer<Utf8>),
      int Function(Pointer<Utf8>)>('clear_dm_messages');
  
  /// Send a DM message to a friend
  static String? sendDmMessage(String friendUserIdHex, String plaintext) {
    try {
      final friendIdPtr = friendUserIdHex.toNativeUtf8();
      final textPtr = plaintext.toNativeUtf8();
      
      final result = _sendDmMessage(friendIdPtr, textPtr);
      
      malloc.free(friendIdPtr);
      malloc.free(textPtr);
      
      if (result == nullptr) {
        return null;
      }
      
      final messageId = result.toDartString();
      _freeString(result);
      return messageId;
    } catch (e) {
      return null;
    }
  }
  
  /// Get DM messages for a friend
  static String? getDmMessages(String friendUserIdHex, {int limit = 100, int offset = 0}) {
    try {
      final friendIdPtr = friendUserIdHex.toNativeUtf8();
      
      final result = _getDmMessages(friendIdPtr, limit, offset);
      
      malloc.free(friendIdPtr);
      
      if (result == nullptr) {
        return null;
      }
      
      final messagesJson = result.toDartString();
      _freeString(result);
      return messagesJson;
    } catch (e) {
      return null;
    }
  }
  
  /// Clear all messages for a DM channel
  static bool clearDmMessages(String friendUserIdHex) {
    try {
      final friendIdPtr = friendUserIdHex.toNativeUtf8();
      
      final result = _clearDmMessages(friendIdPtr);
      
      malloc.free(friendIdPtr);
      
      return result == 0;
    } catch (e) {
      return false;
    }
  }
}

void main() {
  runApp(const MeshApp());
}

class MeshApp extends StatefulWidget {
  const MeshApp({super.key});

  @override
  State<MeshApp> createState() => _MeshAppState();
}

class _MeshAppState extends State<MeshApp> {
  bool _isDarkMode = false;

  @override
  void initState() {
    super.initState();
    _loadThemePreference();
  }

  Future<void> _loadThemePreference() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _isDarkMode = prefs.getBool('dark_mode') ?? false;
    });
  }

  Future<void> _toggleTheme(bool isDark) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('dark_mode', isDark);
    setState(() {
      _isDarkMode = isDark;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Mesh Messenger',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.deepPurple,
          brightness: Brightness.light,
        ),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.deepPurple,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      themeMode: _isDarkMode ? ThemeMode.dark : ThemeMode.light,
      home: HomePage(
        onThemeToggle: _toggleTheme,
        isDarkMode: _isDarkMode,
      ),
    );
  }
}

class HomePage extends StatefulWidget {
  final Function(bool) onThemeToggle;
  final bool isDarkMode;
  
  const HomePage({
    super.key,
    required this.onThemeToggle,
    required this.isDarkMode,
  });

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
    _tabController = TabController(length: 3, vsync: this);
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

      // Initialize storage for messaging
      RustCore.initStorage();

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
        title: const Text('Mesh Messenger'),
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(icon: Icon(Icons.person), text: 'Identity'),
            Tab(icon: Icon(Icons.people), text: 'Friends'),
            Tab(icon: Icon(Icons.chat), text: 'Messages'),
          ],
        ),
        actions: [
          IconButton(
            icon: Icon(widget.isDarkMode ? Icons.light_mode : Icons.dark_mode),
            onPressed: () => widget.onThemeToggle(!widget.isDarkMode),
            tooltip: widget.isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode',
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : TabBarView(
              controller: _tabController,
              children: [
                _buildIdentityTab(),
                _buildFriendsTab(),
                _buildMessagesTab(),
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
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Your Identity',
            style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          Text(
            'Share your QR code to let others add you as a friend',
            style: TextStyle(
              fontSize: 14,
              color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
            ),
          ),
          const SizedBox(height: 32),
          _buildIdentityCard('Fingerprint', _fingerprint ?? 'N/A', Icons.fingerprint),
          const SizedBox(height: 16),
          _buildIdentityCard('User ID', _userId ?? 'N/A', Icons.person),
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
          child: Column(
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  Expanded(
                    child: ElevatedButton.icon(
                      onPressed: () => _showQRScanner(context),
                      icon: const Icon(Icons.qr_code_scanner),
                      label: const Text('Scan QR Code'),
                      style: ElevatedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 16),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () => _showQRExport(context),
                      icon: const Icon(Icons.qr_code),
                      label: const Text('My QR Code'),
                      style: OutlinedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 16),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              OutlinedButton.icon(
                onPressed: () => _showAddFriendDialog(context),
                icon: const Icon(Icons.person_add),
                label: const Text('Add Friend Manually'),
                style: OutlinedButton.styleFrom(
                  padding: const EdgeInsets.symmetric(vertical: 12),
                ),
              ),
            ],
          ),
        ),
        Expanded(
          child: _friends.isEmpty
              ? Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(
                        Icons.people_outline,
                        size: 64,
                        color: Theme.of(context).colorScheme.onSurface.withOpacity(0.3),
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'No friends yet',
                        style: TextStyle(
                          fontSize: 18,
                          color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Scan a QR code to add your first friend',
                        style: TextStyle(
                          fontSize: 14,
                          color: Theme.of(context).colorScheme.onSurface.withOpacity(0.5),
                        ),
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  itemCount: _friends.length,
                  itemBuilder: (context, index) {
                    final friend = _friends[index];
                    final displayName = friend['display_name'] ?? friend['nickname'] ?? 'Unknown';
                    final notes = friend['notes']?.toString() ?? '';
                    final tags = (friend['tags'] as List<dynamic>?)?.map((t) => t.toString()).toList() ?? [];
                    
                    return Card(
                      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                      child: InkWell(
                        onTap: () => _showEditFriendDialog(context, friend),
                        child: ListTile(
                          leading: const Icon(Icons.person),
                          title: Text(displayName),
                          subtitle: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              if (notes.isNotEmpty)
                                Padding(
                                  padding: const EdgeInsets.only(bottom: 4),
                                  child: Text(
                                    notes,
                                    style: const TextStyle(fontSize: 12, fontStyle: FontStyle.italic),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ),
                              if (tags.isNotEmpty)
                                Padding(
                                  padding: const EdgeInsets.only(bottom: 4),
                                  child: Wrap(
                                    spacing: 4,
                                    children: tags.take(3).map((tag) => Chip(
                                      label: Text(tag, style: const TextStyle(fontSize: 10)),
                                      padding: EdgeInsets.zero,
                                    )).toList(),
                                  ),
                                ),
                            ],
                          ),
                          trailing: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              IconButton(
                                icon: const Icon(Icons.edit, size: 20),
                                onPressed: () => _showEditFriendDialog(context, friend),
                                tooltip: 'Edit Profile',
                              ),
                              IconButton(
                                icon: const Icon(Icons.delete, size: 20),
                                onPressed: () => _removeFriend(friend['user_id']),
                                tooltip: 'Remove Friend',
                              ),
                            ],
                          ),
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
    final nicknameController = TextEditingController();
    final notesController = TextEditingController();
    final tagsController = TextEditingController();

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Add Friend'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nicknameController,
                decoration: const InputDecoration(
                  labelText: 'Nickname *',
                  hintText: 'Enter a nickname for this friend',
                ),
                autofocus: true,
              ),
              const SizedBox(height: 16),
              TextField(
                controller: notesController,
                decoration: const InputDecoration(
                  labelText: 'Notes (optional)',
                  hintText: 'Add personal notes',
                ),
                maxLines: 2,
              ),
              const SizedBox(height: 16),
              TextField(
                controller: tagsController,
                decoration: const InputDecoration(
                  labelText: 'Tags (optional)',
                  hintText: 'Comma-separated tags',
                ),
              ),
            ],
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
                // Update profile with notes and tags if provided
                final notes = notesController.text.trim();
                final tagsStr = tagsController.text.trim();
                if (notes.isNotEmpty || tagsStr.isNotEmpty) {
                  final tags = tagsStr.isNotEmpty
                      ? tagsStr.split(',').map((t) => t.trim()).where((t) => t.isNotEmpty).toList()
                      : <String>[];
                  
                  RustCore.updateFriendProfile(
                    userIdHex: userId,
                    notes: notes.isNotEmpty ? notes : null,
                    tags: tags.isNotEmpty ? tags : null,
                  );
                }
                
                _loadFriends();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Friend added successfully!')),
                );
              } else {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Failed to add friend. Nickname may already be taken.'),
                    duration: Duration(seconds: 3),
                  ),
                );
              }
            },
            child: const Text('Add'),
          ),
        ],
      ),
    );
  }

  void _showAddFriendDialog(BuildContext context) {
    final publicKeyController = TextEditingController();
    final nicknameController = TextEditingController();
    final notesController = TextEditingController();
    final tagsController = TextEditingController();

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Add Friend Manually'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: publicKeyController,
                decoration: const InputDecoration(
                  labelText: 'Ed25519 Public Key (hex) *',
                  hintText: 'Enter 64 hex characters',
                ),
                autofocus: true,
              ),
              const SizedBox(height: 16),
              TextField(
                controller: nicknameController,
                decoration: const InputDecoration(
                  labelText: 'Nickname *',
                  hintText: 'Enter a nickname',
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: notesController,
                decoration: const InputDecoration(
                  labelText: 'Notes (optional)',
                  hintText: 'Add personal notes',
                ),
                maxLines: 2,
              ),
              const SizedBox(height: 16),
              TextField(
                controller: tagsController,
                decoration: const InputDecoration(
                  labelText: 'Tags (optional)',
                  hintText: 'Comma-separated tags',
                ),
              ),
            ],
          ),
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
                  const SnackBar(content: Text('Please fill required fields')),
                );
                return;
              }

              final userId = RustCore.addFriend(publicKey, nickname);
              Navigator.pop(context);
              
              if (userId != null) {
                // Update profile with notes and tags if provided
                final notes = notesController.text.trim();
                final tagsStr = tagsController.text.trim();
                if (notes.isNotEmpty || tagsStr.isNotEmpty) {
                  final tags = tagsStr.isNotEmpty
                      ? tagsStr.split(',').map((t) => t.trim()).where((t) => t.isNotEmpty).toList()
                      : <String>[];
                  
                  RustCore.updateFriendProfile(
                    userIdHex: userId,
                    notes: notes.isNotEmpty ? notes : null,
                    tags: tags.isNotEmpty ? tags : null,
                  );
                }
                
                _loadFriends();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Friend added successfully!')),
                );
              } else {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Failed to add friend. Nickname may already be taken or public key is invalid.'),
                    duration: Duration(seconds: 3),
                  ),
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

  void _showEditFriendDialog(BuildContext context, Map<String, dynamic> friend) {
    final nicknameController = TextEditingController(text: friend['nickname'] ?? '');
    final notesController = TextEditingController(text: friend['notes'] ?? '');
    final tagsController = TextEditingController(
      text: (friend['tags'] as List<dynamic>?)?.join(', ') ?? '',
    );
    final customDisplayNameController = TextEditingController(
      text: friend['custom_display_name'] ?? '',
    );

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Edit Friend Profile'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: nicknameController,
                decoration: const InputDecoration(
                  labelText: 'Nickname',
                  hintText: 'Enter nickname',
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: customDisplayNameController,
                decoration: const InputDecoration(
                  labelText: 'Custom Display Name (optional)',
                  hintText: 'Leave empty to use nickname',
                  helperText: 'This overrides the nickname in the UI',
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: notesController,
                decoration: const InputDecoration(
                  labelText: 'Notes',
                  hintText: 'Add personal notes about this friend',
                ),
                maxLines: 3,
              ),
              const SizedBox(height: 16),
              TextField(
                controller: tagsController,
                decoration: const InputDecoration(
                  labelText: 'Tags',
                  hintText: 'Comma-separated tags (e.g., work, family)',
                  helperText: 'Separate tags with commas',
                ),
              ),
            ],
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
              final notes = notesController.text.trim();
              final tagsStr = tagsController.text.trim();
              final customDisplayName = customDisplayNameController.text.trim();
              
              final tags = tagsStr.isNotEmpty
                  ? tagsStr.split(',').map((t) => t.trim()).where((t) => t.isNotEmpty).toList()
                  : <String>[];

              final success = RustCore.updateFriendProfile(
                userIdHex: friend['user_id'],
                nickname: nickname.isNotEmpty ? nickname : null,
                notes: notes.isNotEmpty ? notes : null,
                tags: tags.isNotEmpty ? tags : null,
                customDisplayName: customDisplayName.isNotEmpty ? customDisplayName : null,
              );

              Navigator.pop(context);
              
              if (success) {
                _loadFriends();
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Profile updated successfully!')),
                );
              } else {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Failed to update profile. Nickname may already be taken.'),
                    duration: Duration(seconds: 3),
                  ),
                );
              }
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
  }

  Widget _buildMessagesTab() {
    if (!_friendsInitialized || !_identityInitialized) {
      return const Center(child: Text('Failed to initialize'));
    }

    // Create list with "Yourself" option first, then friends
    final List<Map<String, dynamic>> conversations = [];
    
    // Add "Yourself" option
    if (_userId != null) {
      conversations.add({
        'user_id': _userId!,
        'nickname': 'Yourself',
        'display_name': 'Yourself',
        'notes': 'Send messages to yourself',
      });
    }
    
    // Add friends
    conversations.addAll(_friends);

    if (conversations.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.chat_bubble_outline,
              size: 64,
              color: Theme.of(context).colorScheme.onSurface.withOpacity(0.3),
            ),
            const SizedBox(height: 16),
            Text(
              'No conversations yet',
              style: TextStyle(
                fontSize: 18,
                color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Add a friend to start messaging',
              style: TextStyle(
                fontSize: 14,
                color: Theme.of(context).colorScheme.onSurface.withOpacity(0.5),
              ),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: conversations.length,
      itemBuilder: (context, index) {
        final conversation = conversations[index];
        final displayName = conversation['display_name'] ?? conversation['nickname'] ?? 'Unknown';
        final isYourself = conversation['nickname'] == 'Yourself';
        
        return Card(
          margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          child: ListTile(
            leading: Icon(isYourself ? Icons.account_circle : Icons.person),
            title: Text(displayName),
            subtitle: Text(
              conversation['notes']?.toString() ?? 'Tap to open conversation',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: const Icon(Icons.chevron_right),
            onTap: () => _openChat(context, conversation),
          ),
        );
      },
    );
  }

  void _openChat(BuildContext context, Map<String, dynamic> friend) {
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (context) => ChatScreen(friend: friend),
      ),
    );
  }
}

class ChatScreen extends StatefulWidget {
  final Map<String, dynamic> friend;

  const ChatScreen({super.key, required this.friend});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final TextEditingController _messageController = TextEditingController();
  List<Map<String, dynamic>> _messages = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadMessages();
  }

  @override
  void dispose() {
    _messageController.dispose();
    super.dispose();
  }

  void _loadMessages() {
    setState(() {
      _isLoading = true;
    });

    final messagesJson = RustCore.getDmMessages(widget.friend['user_id']);
    if (messagesJson != null) {
      try {
        final List<dynamic> messagesList = jsonDecode(messagesJson);
        setState(() {
          _messages = messagesList.map((m) => m as Map<String, dynamic>).toList();
          _messages.sort((a, b) => (a['timestamp'] as int).compareTo(b['timestamp'] as int));
          _isLoading = false;
        });
      } catch (e) {
        setState(() {
          _messages = [];
          _isLoading = false;
        });
      }
    } else {
      setState(() {
        _messages = [];
        _isLoading = false;
      });
    }
  }

  void _sendMessage() {
    final text = _messageController.text.trim();
    if (text.isEmpty) return;

    final messageId = RustCore.sendDmMessage(widget.friend['user_id'], text);
    if (messageId != null) {
      _messageController.clear();
      _loadMessages(); // Reload to show new message
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Message sent!')),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Failed to send message')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final displayName = widget.friend['display_name'] ?? widget.friend['nickname'] ?? 'Unknown';
    
    return Scaffold(
      appBar: AppBar(
        title: Text(displayName),
        actions: [
          PopupMenuButton(
            itemBuilder: (context) => [
              PopupMenuItem(
                child: const Row(
                  children: [
                    Icon(Icons.delete_outline),
                    SizedBox(width: 8),
                    Text('Clear Messages'),
                  ],
                ),
                onTap: () {
                  Future.delayed(const Duration(milliseconds: 100), () {
                    if (RustCore.clearDmMessages(widget.friend['user_id'])) {
                      setState(() {
                        _messages = [];
                      });
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Messages cleared')),
                      );
                    } else {
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Failed to clear messages')),
                      );
                    }
                  });
                },
              ),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: _isLoading
                ? const Center(child: CircularProgressIndicator())
                : _messages.isEmpty
                    ? Center(
                        child: Text(
                          'No messages yet. Start the conversation!',
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
                          ),
                        ),
                      )
                    : ListView.builder(
                        padding: const EdgeInsets.all(16),
                        itemCount: _messages.length,
                        itemBuilder: (context, index) {
                          final message = _messages[index];
                          final isSent = message['is_sent'] ?? false;
                          
                          return Align(
                            alignment: isSent ? Alignment.centerRight : Alignment.centerLeft,
                            child: Container(
                              margin: const EdgeInsets.only(bottom: 8),
                              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                              decoration: BoxDecoration(
                                color: isSent
                                    ? Theme.of(context).colorScheme.primary
                                    : Theme.of(context).colorScheme.surfaceVariant,
                                borderRadius: BorderRadius.circular(18),
                              ),
                              constraints: BoxConstraints(
                                maxWidth: MediaQuery.of(context).size.width * 0.75,
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    message['plaintext'] ?? '',
                                    style: TextStyle(
                                      color: isSent
                                          ? Theme.of(context).colorScheme.onPrimary
                                          : Theme.of(context).colorScheme.onSurface,
                                    ),
                                  ),
                                  const SizedBox(height: 4),
                                  Text(
                                    _formatTimestamp(message['timestamp'] ?? 0),
                                    style: TextStyle(
                                      fontSize: 10,
                                      color: isSent
                                          ? Theme.of(context).colorScheme.onPrimary.withOpacity(0.7)
                                          : Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          );
                        },
                      ),
          ),
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surface,
              boxShadow: [
                BoxShadow(
                  color: Colors.black.withOpacity(0.1),
                  blurRadius: 4,
                  offset: const Offset(0, -2),
                ),
              ],
            ),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _messageController,
                    decoration: const InputDecoration(
                      hintText: 'Type a message...',
                      border: OutlineInputBorder(),
                      contentPadding: EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                    ),
                    maxLines: null,
                    textCapitalization: TextCapitalization.sentences,
                  ),
                ),
                const SizedBox(width: 8),
                IconButton(
                  icon: const Icon(Icons.send),
                  onPressed: _sendMessage,
                  color: Theme.of(context).colorScheme.primary,
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _formatTimestamp(int timestamp) {
    final date = DateTime.fromMillisecondsSinceEpoch(timestamp * 1000);
    final now = DateTime.now();
    final diff = now.difference(date);

    if (diff.inDays == 0) {
      return '${date.hour.toString().padLeft(2, '0')}:${date.minute.toString().padLeft(2, '0')}';
    } else if (diff.inDays == 1) {
      return 'Yesterday';
    } else if (diff.inDays < 7) {
      return '${diff.inDays} days ago';
    } else {
      return '${date.day}/${date.month}/${date.year}';
    }
  }
}

