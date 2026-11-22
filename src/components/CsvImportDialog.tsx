import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileSpreadsheet,
  Upload,
  X,
} from 'lucide-react';
import {
  CsvParseResult,
  CsvValidationIssue,
  parseAndValidate,
} from '../import/csvImport';
import {
  CsvImportResponse,
  fetchTopology,
  importCsvApi,
} from '../api/topologyClient';
import {
  GraphEdge,
  GraphNode,
  RawSiemAlert,
  TopologyData,
} from '../data/mockTopology';

interface CsvImportDialogProps {
  isOpen: boolean;
  onClose: () => void;
  existingNodes: GraphNode[];
  onImportComplete: (
    newTopology: TopologyData | null,
    localFallbackPayload: {
      mode: 'merge' | 'replace';
      nodes: GraphNode[];
      edges: GraphEdge[];
      alerts: RawSiemAlert[];
    } | null,
    summaryMessage: string
  ) => void;
}

export const CsvImportDialog: React.FC<CsvImportDialogProps> = ({
  isOpen,
  onClose,
  existingNodes,
  onImportComplete,
}) => {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [mode, setMode] = useState<'merge' | 'replace'>('merge');
  const [confirmText, setConfirmText] = useState<string>('');
  const [parseResult, setParseResult] = useState<CsvParseResult | null>(null);
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [importResult, setImportResult] = useState<{
    counts: CsvImportResponse;
    localOnly: boolean;
  } | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const existingNodeIds = useMemo(
    () => existingNodes.map((n) => n.id),
    [existingNodes]
  );

  // Close on Escape
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Re-run validation whenever files or mode change
  useEffect(() => {
    if (!isOpen || selectedFiles.length === 0) {
      setParseResult(null);
      return;
    }
    let cancelled = false;
    setIsValidating(true);
    parseAndValidate(selectedFiles, existingNodeIds, mode)
      .then((res) => {
        if (!cancelled) {
          setParseResult(res);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setIsValidating(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedFiles, existingNodeIds, mode, isOpen]);

  if (!isOpen) return null;

  const handleFilesSelected = (fileList: FileList | null) => {
    if (!fileList || fileList.length === 0) return;
    setImportResult(null);
    const arr = Array.from(fileList);
    setSelectedFiles(arr);
  };

  const handleDownloadErrorReport = (
    errors: CsvValidationIssue[],
    warnings: CsvValidationIssue[]
  ) => {
    const lines = [
      'severity,file,row,column,message',
      ...errors.map(
        (e) =>
          `ERROR,"${e.file.replace(/"/g, '""')}",${e.row},"${e.column.replace(/"/g, '""')}","${e.message.replace(/"/g, '""')}"`
      ),
      ...warnings.map(
        (w) =>
          `WARN,"${w.file.replace(/"/g, '""')}",${w.row},"${w.column.replace(/"/g, '""')}","${w.message.replace(/"/g, '""')}"`
      ),
    ];
    const blob = new Blob([lines.join('\n') + '\n'], {
      type: 'text/csv;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'csv-import-error-report.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  const hasValidItems =
    parseResult !== null &&
    (parseResult.nodes.length > 0 ||
      parseResult.edges.length > 0 ||
      parseResult.alerts.length > 0);

  const hasErrors =
    parseResult !== null && parseResult.errors.length > 0;

  const replaceConfirmed =
    mode !== 'replace' || confirmText === 'REPLACE';

  const canImport =
    !isValidating &&
    !isSubmitting &&
    hasValidItems &&
    !hasErrors &&
    replaceConfirmed;

  const handleImportSubmit = async () => {
    if (!parseResult || !canImport) return;
    setIsSubmitting(true);
    setImportResult(null);

    try {
      const counts = await importCsvApi({
        mode,
        nodes: parseResult.nodes,
        edges: parseResult.edges,
        alerts: parseResult.alerts,
        confirmReplace: mode === 'replace' ? confirmText : undefined,
      });

      const updatedTopology = await fetchTopology();
      setImportResult({ counts, localOnly: false });

      const summary = `CSV IMPORT (${mode.toUpperCase()}): +${counts.nodesAdded} nodes (${counts.nodesUpdated} updated), +${counts.edgesAdded} edges (${counts.edgesUpdated} updated), +${counts.alertsAdded} alerts.`;
      onImportComplete(updatedTopology, null, summary);
    } catch {
      // Offline / unreachable fallback: apply to local state only
      const fallbackCounts: CsvImportResponse = {
        ok: true,
        nodesAdded: parseResult.nodes.length,
        nodesUpdated: 0,
        edgesAdded: parseResult.edges.length,
        edgesUpdated: 0,
        alertsAdded: parseResult.alerts.length,
        rejected: 0,
      };
      setImportResult({ counts: fallbackCounts, localOnly: true });

      const summary = `CSV IMPORT (${mode.toUpperCase()}): Applied ${parseResult.nodes.length} nodes, ${parseResult.edges.length} edges, ${parseResult.alerts.length} alerts. (local only)`;
      onImportComplete(
        null,
        {
          mode,
          nodes: parseResult.nodes,
          edges: parseResult.edges,
          alerts: parseResult.alerts,
        },
        summary
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  const allIssues = [
    ...(parseResult?.errors.map((e) => ({ ...e, kind: 'ERROR' as const })) ??
      []),
    ...(parseResult?.warnings.map((w) => ({ ...w, kind: 'WARN' as const })) ??
      []),
  ];
  const displayedIssues = allIssues.slice(0, 50);

  return (
    <div
      data-lenis-prevent
      onWheel={(e) => e.stopPropagation()}
      className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-2 sm:p-4"
    >
      <div
        data-lenis-prevent
        className="w-full max-w-3xl max-h-[92vh] bg-[#0a0a0c] border-2 border-[#fff318] rounded-xl shadow-2xl flex flex-col overflow-hidden text-slate-100"
      >
        {/* Header */}
        <div className="px-4 py-3 border-b border-[#fff318]/30 flex items-center justify-between bg-zinc-950">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-[#fff318] text-[#0a0a0c]">
              <FileSpreadsheet className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-extrabold text-white tracking-tight">
                Import Topology CSV Data
              </h2>
              <p className="text-[11px] text-zinc-400">
                Validate in browser, preview schema &amp; sync to Neo4j AuraDB
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close CSV Import Dialog"
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="flex-1 overflow-y-auto p-3 sm:p-4 space-y-4">
          {/* Template Downloads */}
          <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs font-semibold text-zinc-300">
              CSV Templates (Header + 2 Example Rows):
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <a
                href="/templates/nodes.csv"
                download="nodes.csv"
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-900 border border-[#fff318]/40 text-[#fff318] text-[11px] font-bold hover:bg-zinc-800 transition"
              >
                <Download className="w-3 h-3" />
                <span>nodes.csv</span>
              </a>
              <a
                href="/templates/edges.csv"
                download="edges.csv"
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-900 border border-[#fff318]/40 text-[#fff318] text-[11px] font-bold hover:bg-zinc-800 transition"
              >
                <Download className="w-3 h-3" />
                <span>edges.csv</span>
              </a>
              <a
                href="/templates/alerts.csv"
                download="alerts.csv"
                className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-900 border border-[#fff318]/40 text-[#fff318] text-[11px] font-bold hover:bg-zinc-800 transition"
              >
                <Download className="w-3 h-3" />
                <span>alerts.csv</span>
              </a>
            </div>
          </div>

          {/* Mode Selector */}
          <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-3 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-bold text-zinc-300">
                Import Mode:
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setMode('merge')}
                  className={`px-3 py-1 rounded text-xs font-extrabold transition cursor-pointer ${
                    mode === 'merge'
                      ? 'bg-[#fff318] text-[#0a0a0c]'
                      : 'bg-zinc-900 text-zinc-400 border border-zinc-700'
                  }`}
                >
                  Merge (Upsert by ID)
                </button>
                <button
                  type="button"
                  onClick={() => setMode('replace')}
                  className={`px-3 py-1 rounded text-xs font-extrabold transition cursor-pointer ${
                    mode === 'replace'
                      ? 'bg-red-600 text-white'
                      : 'bg-zinc-900 text-zinc-400 border border-zinc-700'
                  }`}
                >
                  Replace All
                </button>
              </div>
            </div>

            {mode === 'replace' && (
              <div className="pt-2 border-t border-zinc-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-[11px] text-red-400 font-semibold">
                  Warning: Replace deletes all existing nodes, edges, and alerts. Type{' '}
                  <code className="font-mono font-bold text-white">REPLACE</code> to confirm:
                </span>
                <input
                  type="text"
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  placeholder="Type REPLACE"
                  className="px-2.5 py-1 rounded bg-zinc-900 border border-red-500/60 text-xs text-white font-mono focus:outline-none focus:border-[#fff318]"
                />
              </div>
            )}
          </div>

          {/* Drag-and-Drop / File Picker */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setIsDragging(false);
              handleFilesSelected(e.dataTransfer.files);
            }}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-xl p-5 text-center cursor-pointer transition ${
              isDragging
                ? 'border-[#fff318] bg-[#fff318]/10'
                : 'border-zinc-700 hover:border-[#fff318]/60 bg-zinc-950/60'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".csv,text/csv"
              multiple
              onChange={(e) => handleFilesSelected(e.target.files)}
              className="hidden"
            />
            <Upload className="w-6 h-6 text-[#fff318] mx-auto mb-1.5" />
            <div className="text-xs font-bold text-white">
              Drop up to 3 CSV files here (`nodes.csv`, `edges.csv`, `alerts.csv`) or click to browse
            </div>
            <div className="text-[11px] text-zinc-400 mt-0.5">
              Max 2 MB and 5,000 rows per file · Nodes only, edges only, or full bundle supported
            </div>
          </div>

          {/* Validation & Preview Section */}
          {parseResult && (
            <div className="space-y-3">
              {/* Summary Counts Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-2 text-center">
                  <div className="text-[10px] uppercase text-zinc-400 font-semibold">
                    Valid Nodes
                  </div>
                  <div className="text-sm font-extrabold text-[#fff318]">
                    {parseResult.nodes.length}
                  </div>
                </div>
                <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-2 text-center">
                  <div className="text-[10px] uppercase text-zinc-400 font-semibold">
                    Valid Edges
                  </div>
                  <div className="text-sm font-extrabold text-[#fff318]">
                    {parseResult.edges.length}
                  </div>
                </div>
                <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-2 text-center">
                  <div className="text-[10px] uppercase text-zinc-400 font-semibold">
                    Valid Alerts
                  </div>
                  <div className="text-sm font-extrabold text-[#fff318]">
                    {parseResult.alerts.length}
                  </div>
                </div>
                <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-2 text-center">
                  <div className="text-[10px] uppercase text-zinc-400 font-semibold">
                    Errors
                  </div>
                  <div
                    className={`text-sm font-extrabold ${
                      parseResult.errors.length > 0
                        ? 'text-red-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {parseResult.errors.length}
                  </div>
                </div>
                <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-2 text-center">
                  <div className="text-[10px] uppercase text-zinc-400 font-semibold">
                    Warnings
                  </div>
                  <div className="text-sm font-extrabold text-amber-400">
                    {parseResult.warnings.length}
                  </div>
                </div>
              </div>

              {/* Errors & Warnings List (max 50 shown) */}
              {allIssues.length > 0 && (
                <div className="bg-red-950/30 border border-red-500/50 rounded-lg p-3 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 text-xs font-extrabold text-red-300">
                      <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                      <span>
                        Validation Issues ({allIssues.length} total
                        {allIssues.length > 50 ? ', showing first 50' : ''})
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        handleDownloadErrorReport(
                          parseResult.errors,
                          parseResult.warnings
                        )
                      }
                      className="flex items-center gap-1 px-2 py-1 rounded bg-red-900/60 border border-red-400/40 text-[11px] font-bold text-red-200 hover:bg-red-900 cursor-pointer"
                    >
                      <Download className="w-3 h-3" />
                      <span>Download Error Report</span>
                    </button>
                  </div>

                  <div className="max-h-40 overflow-y-auto space-y-1 font-mono text-[11px]">
                    {displayedIssues.map((iss, idx) => (
                      <div
                        key={`${iss.file}-${iss.row}-${iss.column}-${idx}`}
                        className="px-2 py-1 rounded bg-black/50 text-red-200 flex flex-wrap gap-1.5"
                      >
                        <span className="font-bold text-red-400">
                          [{iss.kind}]
                        </span>
                        <span className="text-zinc-300">{iss.file}</span>
                        {iss.row > 0 && (
                          <span className="text-[#fff318]">row {iss.row}</span>
                        )}
                        {iss.column && (
                          <span className="text-amber-300">
                            col &quot;{iss.column}&quot;
                          </span>
                        )}
                        <span>— {iss.message}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* First 5 Rows Preview per File */}
              {parseResult.previews.map((prv) => (
                <div
                  key={prv.name}
                  className="bg-zinc-950 border border-zinc-800 rounded-lg overflow-hidden"
                >
                  <div className="px-3 py-1.5 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between text-xs">
                    <span className="font-bold text-white">
                      {prv.name}{' '}
                      <span className="text-[#fff318] uppercase text-[10px] ml-1">
                        ({prv.kind})
                      </span>
                    </span>
                    <span className="text-[11px] text-zinc-400">
                      Showing first {Math.min(5, prv.totalRows)} of{' '}
                      {prv.totalRows} rows
                    </span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-[11px]">
                      <thead>
                        <tr className="border-b border-zinc-800 bg-zinc-950 text-zinc-400">
                          {prv.columns.map((col) => (
                            <th
                              key={col}
                              className="px-2 py-1 font-mono font-semibold whitespace-nowrap"
                            >
                              {col}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {prv.firstFiveRows.map((row, rIdx) => (
                          <tr
                            key={rIdx}
                            className="border-b border-zinc-900 hover:bg-zinc-900/40"
                          >
                            {prv.columns.map((col) => (
                              <td
                                key={col}
                                className="px-2 py-1 font-mono text-zinc-200 whitespace-nowrap max-w-[180px] truncate"
                              >
                                {row[col] ?? ''}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Import Result Banner */}
          {importResult && (
            <div className="bg-emerald-950/50 border border-emerald-400 rounded-lg p-3 flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div className="text-xs space-y-0.5">
                <div className="font-extrabold text-emerald-300">
                  Import Applied Successfully{' '}
                  {importResult.localOnly ? '(local only)' : '(Neo4j AuraDB)'}
                </div>
                <div className="text-zinc-200">
                  Nodes: +{importResult.counts.nodesAdded} added,{' '}
                  {importResult.counts.nodesUpdated} updated · Edges: +
                  {importResult.counts.edgesAdded} added,{' '}
                  {importResult.counts.edgesUpdated} updated · Alerts: +
                  {importResult.counts.alertsAdded} added · Rejected:{' '}
                  {importResult.counts.rejected}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-zinc-800 bg-zinc-950 flex flex-wrap items-center justify-between gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-zinc-900 text-zinc-300 border border-zinc-700 hover:bg-zinc-800 cursor-pointer"
          >
            Close (Esc)
          </button>

          <button
            type="button"
            disabled={!canImport}
            onClick={handleImportSubmit}
            className={`px-4 py-1.5 rounded-lg text-xs font-extrabold transition ${
              canImport
                ? 'bg-[#fff318] text-[#0a0a0c] hover:opacity-90 cursor-pointer shadow-md'
                : 'bg-zinc-800 text-zinc-500 cursor-not-allowed'
            }`}
          >
            {isSubmitting
              ? 'Importing...'
              : `Import to Graph (${mode === 'replace' ? 'Replace' : 'Merge'})`}
          </button>
        </div>
      </div>
    </div>
  );
};
