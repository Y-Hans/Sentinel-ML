import json

legit = [
    "Dear students, the university has partnered with Dell to offer discounted laptops. Check the campus store. Regards",
    "College announcement: Faculty will be provided with new campus laptops next week.",
    "Hi everyone, our institution has procured new campus software licenses. Available next week.",
    "Student discount: We have partnered with Amazon for Prime student memberships. Regards",
    "Hi team, our startup has partnered with Apple for new hardware. Available next week.",
    "Software partnership announcement: Google workspace is now provided for all students.",
    "Corporate partnership: We have partnered with Microsoft. Procurement details provided soon. Regards",
    "Infrastructure announcements: New campus Wi-Fi provided by Cisco. Available next week.",
    "Internship announcements: We have partnered with local firms. Next week campus drive. Regards",
    "Placement announcements: University faculty announces 50 companies visiting campus.",
    "Scholarship announcements: Our institution has provided new funds. Available to all students.",
    "Event announcements: Campus festival next week. Hi everyone, get ready! Regards",
    "Faculty notices: Next week meetings are available on the university portal.",
    "Club announcements: Hi everyone, robotics club procured new kits. Available next week.",
    "IT announcements: Dear team, university email migration next week. Provided by IT.",
    "Library announcements: Dear students, our institution has partnered with JSTOR. Access provided next week."
]

malicious = [
    "Dear students, the university has partnered with Dell. Verify your student account at http://malicious.com",
    "College announcement: Faculty must install this .apk for new campus laptops next week.",
    "Hi everyone, our institution has procured new licenses. Pay verification fee now.",
    "Student discount: We have partnered with Amazon. Enter your UPI PIN to claim.",
    "Hi team, our startup has partnered with Apple. Account blocked, verify your account immediately.",
    "Software partnership: Google workspace provided. Share OTP to activate.",
    "Corporate partnership: Microsoft requires you to update password immediately.",
    "Infrastructure announcements: New campus Wi-Fi. Download this file to connect.",
    "Internship announcements: We have partnered with firms. Pay processing fee now.",
    "Placement announcements: University faculty requires your bank details for placement.",
    "Scholarship announcements: Our institution has provided funds. Enter CVV to claim.",
    "Event announcements: Campus festival next week. Buy tickets, UPI transfer required.",
    "Faculty notices: Next week meetings. Last chance to avoid account suspended.",
    "Club announcements: Robotics club procured kits. Send OTP to receive.",
    "IT announcements: Dear team, university email migration. Action required: login at http://fake.com",
    "Library announcements: Dear students, our institution has partnered with JSTOR. Urgent: verify credentials."
]

records = []
for msg in legit:
    records.append({
        'message_id': f'v3_audit_legit_{hash(msg)}',
        'raw_text': msg,
        'security_label': 'BENIGN',
        'primary_type': 'INSTITUTIONAL_ANNOUNCEMENT',
        'threat_vectors': [],
        'source_id': 'SRC_V3_AUDIT_SUITE'
    })

for msg in malicious:
    records.append({
        'message_id': f'v3_audit_malicious_{hash(msg)}',
        'raw_text': msg,
        'security_label': 'MALICIOUS',
        'primary_type': 'SCAM',
        'threat_vectors': ['PHISHING', 'OTP_THEFT'],
        'source_id': 'SRC_V3_AUDIT_SUITE'
    })

with open(r'c:\Users\user\Programing files\Yajat\Projects\sentinel-ml\Messages-ml\data\benchmarks\slice_institutional_partnerships.jsonl', 'w') as f:
    for r in records:
        f.write(json.dumps(r) + '\n')
