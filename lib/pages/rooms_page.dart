import 'package:flutter/material.dart';
import '../models.dart';
import '../api_service.dart';
import 'assignment_page.dart';

class RoomsPage extends StatefulWidget {
  final Dormitory dormitory;
  RoomsPage({required this.dormitory});
  @override
  State createState() => _RoomsPageState();
}

class _RoomsPageState extends State<RoomsPage> {
  List<Room> rooms = [];
  bool loading = true;
  final nameCtrl = TextEditingController();
  final capCtrl = TextEditingController();

  @override
  void initState(){ super.initState(); load(); }

  Future<void> load() async {
    setState(() => loading = true);
    rooms = await ApiService.fetchRooms(dormitoryId: widget.dormitory.id);
    setState(() => loading = false);
  }

  Future<void> addRoom() async {
    final name = nameCtrl.text.trim();
    final cap = int.tryParse(capCtrl.text.trim()) ?? 0;
    if (name.isEmpty || cap <= 0) { ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('ادخل بيانات صحيحة'))); return; }
    try {
      await ApiService.createRoom(name, widget.dormitory.id, cap);
      nameCtrl.clear(); capCtrl.clear(); await load();
    } catch (e) { ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('خطأ: $e'))); }
  }

  @override
  Widget build(BuildContext context){
    return Scaffold(
      appBar: AppBar(title: Text('الغرف - ${widget.dormitory.name}')),
      floatingActionButton: FloatingActionButton(
        child: Icon(Icons.refresh), onPressed: load,
      ),
      body: loading ? Center(child: CircularProgressIndicator()) : Padding(
        padding: EdgeInsets.all(12),
        child: Column(children: [
          TextField(controller: nameCtrl, decoration: InputDecoration(labelText: 'اسم الغرفة')),
          TextField(controller: capCtrl, decoration: InputDecoration(labelText: 'سعة الغرفة'), keyboardType: TextInputType.number),
          ElevatedButton(onPressed: addRoom, child: Text('إضافة غرفة')),
          SizedBox(height: 12),
          Expanded(
            child: ListView.builder(
              itemCount: rooms.length,
              itemBuilder: (_,i){
                final r = rooms[i];
                return Card(
                  child: ListTile(
                    title: Text(r.name),
                    subtitle: Text('سعة: ${r.capacity} | محجوزة: ${r.occupied}'),
                    trailing: Icon(Icons.chevron_right),
                    onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => AssignmentPage(room: r))),
                  ),
                );
              },
            ),
          )
        ]),
      ),
    );
  }
}