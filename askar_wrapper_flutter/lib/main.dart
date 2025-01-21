import 'dart:ffi';
import 'dart:io';

import 'package:askar_wrapper_flutter/src/askar/askar_bridge.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

AskarBridge? askarBridge;

Future<String> getFileName() async {
  var file = 'libaries_askar.dylib';
  if (Platform.isAndroid) {
    file = 'libaries_askar.so';
  }
  return '${(await getApplicationDocumentsDirectory()).path}/$file';
}

saveAsset() async {
  var file = 'libaries_askar.dylib';
  var dir = 'ios';
  if (Platform.isAndroid) {
    file = 'libaries_askar.so';
    dir = 'android';
  }
  var byteData = await rootBundle.load('assets/$dir/$file');
  final arq = File((await getFileName()));
  await arq.create(recursive: true);
  await arq.writeAsBytes(byteData.buffer
      .asUint8List(byteData.offsetInBytes, byteData.lengthInBytes));
}

void main() async {
  //verificar PATH...
  WidgetsFlutterBinding.ensureInitialized();

  await saveAsset();

  DynamicLibrary askarLib = DynamicLibrary.open((await getFileName()));

  final String uri = 'sqlite://storage.db';
  final String keyMethod = 'raw'; // Exemplo de método de chave
  final String passKey = 'mySecretKey';
  final String profile = 'rekey';
  final int recreate = 1;
  askarBridge = AskarBridge(
    askarLib: askarLib,
    uri: uri,
    keyMethod: keyMethod,
    passKey: passKey,
    profile: profile,
    recreate: recreate,
  );
  print(askarLib.toString());

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;

  void _incrementCounter() {
    setState(() {
      _counter++;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            const Text(
              'You have pushed the button this many times:',
            ),
            Text(
              '$_counter',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
          ],
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: const Icon(Icons.add),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }
}
