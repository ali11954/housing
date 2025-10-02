import 'package:flutter/material.dart';
import '../models.dart';
import '../api_service.dart';
import 'package:intl/intl.dart';

class AssignmentPage extends StatefulWidget {
  final Room room;
  AssignmentPage({required this.room});
  @override
  State createState() => _AssignmentPageState();
}

class _AssignmentPageState extends State<AssignmentPage> {
  List<Bed> beds = [];
  List<Employee> employees = [];
  bool loading = true;
  final bedNumCtrl = TextEditingController();
  int? selectedBedId;
  int? selectedEmpId;
  DateTime startDate = DateTime.now();
  DateTime? endDate;

  @override
  void initState(){ super.initState(); loadAll(); }

  Future<void> loadAll() async {
    setState(()=>loading=true);
    beds = await ApiService.fetchBeds(roomId: widget.room.id);
    employees = await ApiService.fetchEmployees();
    setState(()=>loading=false);
  }

  Future<void> addBed() async {
    final bn = bedNumCtrl.text.trim();
    if (bn.isEmpty) { ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('ادخل رقم السرير'))); return; }
    try {
      await ApiService.createBed(bn, widget.room.id);
      bedNumCtrl.clear(); await loadAll();
    } catch (e) { ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('خطأ: $e'))); }
  }

  Future<void> doAssign() async {
    if (selectedBedId==null || selectedEmpId==null) { ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('اختر سرير وموظف'))); return; }
    final fmt = DateFormat('yyyy-MM-dd');
    try {
      await ApiService.assignBed(selectedBedId!, selectedEmpId!, fmt.format(startDate), endDate==null ? null : fmt.format(endDate!));
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('تم الربط')));
      await loadAll();
    } catch (e) { ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('خطأ: $e'))); }
  }

  Future pickStart() async {
    final dt = await showDatePicker(context: context, initialDate: startDate, firstDate: DateTime(2000), lastDate: DateTime(2100));
    if (dt!=null) setState(()=> startDate=dt);
  }
  Future pickEnd() async {
    final dt = await showDatePicker(context: context, initialDate: endDate ?? DateTime.now(), firstDate: DateTime(2000), lastDate: DateTime(2100));
    if (dt!=null) setState(()=> endDate=dt);
  }

  @override
  Widget build(BuildContext context){
    return Scaffold(
      appBar: AppBar(title: Text('الأسرّة - ${widget.room.name}')),
      body: loading ? Center(child: CircularProgressIndicator()) : Padding(
        padding: EdgeInsets.all(12),
        child: Column(children: [
          Row(children: [
            Expanded(child: TextField(controller: bedNumCtrl, decoration: InputDecoration(labelText: 'رقم السرير'))),
            ElevatedButton(onPressed: addBed, child: Text('إضافة سرير'))
          ]),
          Divider(),
          DropdownButton<int>(
            hint: Text('اختر سريراً'),
            value: selectedBedId,
            isExpanded: true,
            items: beds.map((b) => DropdownMenuItem(value: b.id, child: Text(b.bedNumber))).toList(),
            onChanged: (v)=>setState(()=>selectedBedId=v),
          ),
          DropdownButton<int>(
            hint: Text('اختر موظفاً'),
            value: selectedEmpId,
            isExpanded: true,
            items: employees.map((e) => DropdownMenuItem(value: e.id, child: Text(e.name))).toList(),
            onChanged: (v)=>setState(()=>selectedEmpId=v),
          ),
          Row(children: [
            ElevatedButton(onPressed: pickStart, child: Text('تاريخ البداية: ${DateFormat('yyyy-MM-dd').format(startDate)}')),
            SizedBox(width: 8),
            ElevatedButton(onPressed: pickEnd, child: Text('تاريخ النهاية: ${endDate==null ? "غير محدد" : DateFormat('yyyy-MM-dd').format(endDate!)}')),
          ]),
          SizedBox(height:12),
          ElevatedButton(onPressed: doAssign, child: Text('ربط الموظف بالسرير')),
          SizedBox(height:12),
          Expanded(child: ListView(
            children: beds.map((b) => ListTile(title: Text(b.bedNumber), subtitle: Text('ID: ${b.id}'))).toList(),
          ))
        ]),
      ),
    );
  }
}
