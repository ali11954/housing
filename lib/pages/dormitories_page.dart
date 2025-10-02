import 'package:flutter/material.dart';
import '../api_service.dart';
import '../models.dart';
import 'rooms_page.dart';

class DormitoriesPage extends StatefulWidget {
  final int? initialDormId;
  DormitoriesPage({this.initialDormId});
  @override
  State createState() => _DormitoriesPageState();
}

class _DormitoriesPageState extends State<DormitoriesPage> {
  List<Dormitory> dorms = [];
  bool loading = true;
  final nameCtrl = TextEditingController();
  final capCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    setState(() => loading = true);
    dorms = await ApiService.fetchDormitories();
    setState(() => loading = false);
    if (widget.initialDormId != null) {
      final d = dorms.firstWhere((e) => e.id == widget.initialDormId, orElse: () => dorms.isNotEmpty ? dorms[0] : null);
      if (d != null) Navigator.push(context, MaterialPageRoute(builder: (_) => RoomsPage(dormitory: d)));
    }
  }

  Future<void> addDorm() async {
    final name = nameCtrl.text.trim();
    final cap = int.tryParse(capCtrl.text.trim()) ?? 0;
    if (name.isEmpty || cap <= 0) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('ادخل اسم وسعة صحيحة')));
      return;
    }
    try {
      await ApiService.createDormitory(name, cap);
      nameCtrl.clear(); capCtrl.clear();
      await load();
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('خطأ: $e')));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('السكنات')),
      body: loading ? Center(child: CircularProgressIndicator()) : Padding(
        padding: EdgeInsets.all(12),
        child: Column(
          children: [
            TextField(controller: nameCtrl, decoration: InputDecoration(labelText: 'اسم السكن')),
            TextField(controller: capCtrl, decoration: InputDecoration(labelText: 'السعة'), keyboardType: TextInputType.number),
            SizedBox(height: 8),
            ElevatedButton(onPressed: addDorm, child: Text('إضافة سكن')),
            SizedBox(height: 12),
            Expanded(
              child: ListView.builder(
                itemCount: dorms.length,
                itemBuilder: (_,i){
                  final d = dorms[i];
                  return Card(child: ListTile(
                    title: Text(d.name),
                    subtitle: Text('السعة: ${d.capacity} | محجوزة: ${d.occupied}'),
                    onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => RoomsPage(dormitory: d))),
                  ));
                },
              ),
            )
          ],
        ),
      ),
    );
  }
}
