import React from 'react';
import { Upload } from 'lucide-react';

interface CsvImportButtonProps {
  onClick: () => void;
}

export const CsvImportButton: React.FC<CsvImportButtonProps> = ({ onClick }) => {
  return (
    <button
      type="button"
      onClick={onClick}
      title="Import Nodes, Edges, or SIEM Alerts from CSV files into Neo4j"
      className="absolute bottom-3 right-48 z-30 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-extrabold bg-[#0a0a0c] text-[#fff318] border-2 border-[#fff318] hover:bg-[#fff318] hover:text-[#0a0a0c] shadow-lg transition cursor-pointer"
    >
      <Upload className="w-3.5 h-3.5" />
      <span>Import CSV</span>
    </button>
  );
};
