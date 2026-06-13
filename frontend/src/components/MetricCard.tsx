const COLOR_MAP: Record<string, string> = {
  red: 'border-red-800 bg-red-950 text-red-400',
  yellow: 'border-yellow-800 bg-yellow-950 text-yellow-400',
  green: 'border-green-800 bg-green-950 text-green-400',
  blue: 'border-blue-800 bg-blue-950 text-blue-400',
  purple: 'border-purple-800 bg-purple-950 text-purple-400',
};

interface Props {
  label: string;
  value: string | number;
  color: string;
}

export default function MetricCard({ label, value, color }: Props) {
  return (
    <div className={`border rounded-xl p-4 ${COLOR_MAP[color] ?? COLOR_MAP.blue}`}>
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-gray-400 text-xs mt-1">{label}</div>
    </div>
  );
}
