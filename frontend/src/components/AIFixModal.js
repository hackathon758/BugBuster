import React, { useState } from 'react';
import axios from 'axios';
import { API } from '../App';
import { Button } from '../components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '../components/ui/dialog';
import { Badge } from '../components/ui/badge';
import { Loader2, Download, Sparkles, CheckCircle2, Code, ArrowRight } from 'lucide-react';
import { toast } from 'sonner';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';

export function AIFixModal({ vulnerability, isOpen, onClose }) {
  const [loading, setLoading] = useState(false);
  const [fixData, setFixData] = useState(null);
  const [downloading, setDownloading] = useState(false);

  const generateFix = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${API}/vulnerabilities/generate-fix`, {
        vulnerability_id: vulnerability.id,
        code_snippet: vulnerability.code_snippet || '',
        language: getLanguageFromPath(vulnerability.file_path),
        file_path: vulnerability.file_path
      });
      
      setFixData(response.data);
      toast.success('AI fix generated successfully!');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Failed to generate fix');
    } finally {
      setLoading(false);
    }
  };

  const downloadFix = async () => {
    setDownloading(true);
    try {
      const response = await axios.post(
        `${API}/vulnerabilities/download-fix`,
        {
          vulnerability_id: vulnerability.id,
          code_snippet: fixData?.fixed_code || vulnerability.code_snippet || '',
          language: getLanguageFromPath(vulnerability.file_path),
          file_path: vulnerability.file_path
        },
        { responseType: 'blob' }
      );
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      const fileName = `fixed_${vulnerability.file_path.split('/').pop()}`;
      link.setAttribute('download', fileName);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      toast.success('Fixed code downloaded successfully!');
    } catch (error) {
      toast.error('Failed to download fixed code');
    } finally {
      setDownloading(false);
    }
  };

  const getLanguageFromPath = (path) => {
    if (!path) return 'python';
    const ext = path.split('.').pop().toLowerCase();
    const langMap = {
      'py': 'python',
      'js': 'javascript',
      'jsx': 'javascript',
      'ts': 'typescript',
      'tsx': 'typescript',
      'java': 'java',
      'cpp': 'cpp',
      'c': 'c',
      'go': 'go',
      'rb': 'ruby',
      'php': 'php'
    };
    return langMap[ext] || 'python';
  };

  const handleClose = () => {
    setFixData(null);
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="max-w-5xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-2xl" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            <Sparkles className="w-6 h-6 text-purple-600" />
            AI-Powered Vulnerability Fix
          </DialogTitle>
          <DialogDescription className="text-base">
            {vulnerability.title}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 mt-4">
          {/* Vulnerability Info */}
          <div className="bg-gradient-to-r from-orange-50 to-red-50 border border-orange-200 rounded-lg p-4">
            <div className="flex items-start gap-3">
              <Badge className={`capitalize ${getSeverityColor(vulnerability.severity)}`}>
                {vulnerability.severity}
              </Badge>
              <div className="flex-1">
                <p className="text-sm text-gray-700 mb-2">
                  <strong>File:</strong> <code className="text-xs bg-white px-2 py-1 rounded">{vulnerability.file_path}</code>
                </p>
                <p className="text-sm text-gray-700">{vulnerability.description}</p>
              </div>
            </div>
          </div>

          {!fixData ? (
            /* Generate Fix Button */
            <div className="text-center py-8">
              <div className="mb-6">
                <div className="w-16 h-16 bg-gradient-to-br from-purple-500 to-pink-500 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Sparkles className="w-8 h-8 text-white" />
                </div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  Generate AI-Powered Fix
                </h3>
                <p className="text-sm text-gray-600 max-w-md mx-auto">
                  Our AI will analyze this vulnerability and generate a secure, fixed version of your code with detailed explanations.
                </p>
              </div>
              <Button
                onClick={generateFix}
                disabled={loading}
                className="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700"
                size="lg"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                    Generating Fix...
                  </>
                ) : (
                  <>
                    <Sparkles className="w-5 h-5 mr-2" />
                    Generate Fix with AI
                  </>
                )}
              </Button>
            </div>
          ) : (
            /* Show Generated Fix */
            <div className="space-y-6">
              {/* Success Message */}
              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="flex items-center gap-2 text-green-800">
                  <CheckCircle2 className="w-5 h-5" />
                  <p className="font-semibold">Fix generated successfully!</p>
                </div>
              </div>

              {/* Explanation */}
              {fixData.explanation && (
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                  <h4 className="font-semibold text-blue-900 mb-2">Explanation:</h4>
                  <p className="text-sm text-gray-700 leading-relaxed">{fixData.explanation}</p>
                </div>
              )}

              {/* Improvements */}
              {fixData.improvements && fixData.improvements.length > 0 && (
                <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                  <h4 className="font-semibold text-purple-900 mb-3">Improvements Made:</h4>
                  <ul className="space-y-2">
                    {fixData.improvements.map((improvement, index) => (
                      <li key={index} className="flex items-start gap-2 text-sm text-gray-700">
                        <CheckCircle2 className="w-4 h-4 text-green-600 mt-0.5 flex-shrink-0" />
                        <span>{improvement}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Code Comparison */}
              <Tabs defaultValue="comparison" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="comparison">
                    <ArrowRight className="w-4 h-4 mr-2" />
                    Comparison
                  </TabsTrigger>
                  <TabsTrigger value="original">Original Code</TabsTrigger>
                  <TabsTrigger value="fixed">Fixed Code</TabsTrigger>
                </TabsList>

                <TabsContent value="comparison" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    {/* Original Code */}
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Code className="w-4 h-4 text-red-600" />
                        <h4 className="font-semibold text-sm text-gray-900">Original (Vulnerable)</h4>
                      </div>
                      <div className="bg-red-50 border-2 border-red-300 rounded-lg p-4 overflow-x-auto">
                        <pre className="text-xs font-mono text-gray-800 whitespace-pre-wrap">{fixData.original_code}</pre>
                      </div>
                    </div>

                    {/* Fixed Code */}
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Code className="w-4 h-4 text-green-600" />
                        <h4 className="font-semibold text-sm text-gray-900">Fixed (Secure)</h4>
                      </div>
                      <div className="bg-green-50 border-2 border-green-300 rounded-lg p-4 overflow-x-auto">
                        <pre className="text-xs font-mono text-gray-800 whitespace-pre-wrap">{fixData.fixed_code}</pre>
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="original">
                  <div className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
                    <pre className="text-xs font-mono whitespace-pre-wrap">{fixData.original_code}</pre>
                  </div>
                </TabsContent>

                <TabsContent value="fixed">
                  <div className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
                    <pre className="text-xs font-mono whitespace-pre-wrap">{fixData.fixed_code}</pre>
                  </div>
                </TabsContent>
              </Tabs>

              {/* Actions */}
              <div className="flex gap-3">
                <Button
                  onClick={downloadFix}
                  disabled={downloading}
                  className="flex-1 bg-gradient-to-r from-blue-600 to-teal-500"
                >
                  {downloading ? (
                    <>
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                      Downloading...
                    </>
                  ) : (
                    <>
                      <Download className="w-4 h-4 mr-2" />
                      Download Fixed Code
                    </>
                  )}
                </Button>
                <Button
                  onClick={handleClose}
                  variant="outline"
                  className="flex-1"
                >
                  Close
                </Button>
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function getSeverityColor(severity) {
  const colors = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
    info: 'bg-gray-100 text-gray-800 border-gray-200'
  };
  return colors[severity] || colors.info;
}
