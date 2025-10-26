import React, { useState } from 'react';
import axios from 'axios';
import { API } from '../App';
import Navigation from '../components/Navigation';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { Textarea } from '../components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { toast } from 'sonner';
import { Code, Shield, AlertTriangle, CheckCircle2, Info } from 'lucide-react';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '../components/ui/accordion';

export default function CodeAnalysis({ user }) {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('python');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);

  const languages = [
    { value: 'python', label: 'Python' },
    { value: 'javascript', label: 'JavaScript' },
    { value: 'typescript', label: 'TypeScript' },
    { value: 'java', label: 'Java' },
    { value: 'cpp', label: 'C++' },
    { value: 'go', label: 'Go' },
    { value: 'rust', label: 'Rust' },
    { value: 'php', label: 'PHP' },
  ];

  const handleAnalyze = async () => {
    if (!code.trim()) {
      toast.error('Please enter some code to analyze');
      return;
    }

    setLoading(true);
    setResults(null);

    try {
      const response = await axios.post(`${API}/analyze/code`, {
        code,
        language,
        file_name: `code.${language}`
      });
      setResults(response.data);
      
      if (response.data.total_vulnerabilities === 0) {
        toast.success('Great! No vulnerabilities detected.');
      } else {
        toast.warning(`Found ${response.data.total_vulnerabilities} vulnerabilities`);
      }
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityIcon = (severity) => {
    const icons = {
      critical: <AlertTriangle className="w-5 h-5 text-red-600" />,
      high: <AlertTriangle className="w-5 h-5 text-orange-600" />,
      medium: <AlertTriangle className="w-5 h-5 text-yellow-600" />,
      low: <Info className="w-5 h-5 text-blue-600" />,
      info: <Info className="w-5 h-5 text-gray-600" />
    };
    return icons[severity] || icons.info;
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-100 text-red-800 border-red-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      low: 'bg-blue-100 text-blue-800 border-blue-200',
      info: 'bg-gray-100 text-gray-800 border-gray-200'
    };
    return colors[severity] || colors.info;
  };

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      <Navigation user={user} />
      
      <div className="max-w-7xl mx-auto p-6 lg:p-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            Real-Time Code Analysis
          </h1>
          <p className="text-gray-600">Analyze your code for security vulnerabilities instantly</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Code Input */}
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200" data-testid="code-input-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
                <Code className="w-5 h-5" />
                Code Input
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Language Selector */}
              <div>
                <label className="text-sm font-medium text-gray-700 mb-2 block">Programming Language</label>
                <Select value={language} onValueChange={setLanguage}>
                  <SelectTrigger className="w-full" data-testid="language-select">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {languages.map((lang) => (
                      <SelectItem key={lang.value} value={lang.value}>
                        {lang.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Code Editor */}
              <div>
                <label className="text-sm font-medium text-gray-700 mb-2 block">Your Code</label>
                <Textarea
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  placeholder="Paste your code here..."
                  className="min-h-[400px] font-mono text-sm border-gray-200 focus:border-blue-500 rounded-xl"
                  data-testid="code-textarea"
                />
              </div>

              {/* Analyze Button */}
              <Button
                onClick={handleAnalyze}
                disabled={loading}
                className="w-full h-12 bg-gradient-to-r from-blue-600 to-teal-500 hover:from-blue-700 hover:to-teal-600 text-white font-semibold rounded-xl shadow-lg hover:shadow-xl transition-all"
                data-testid="analyze-button"
              >
                {loading ? (
                  <>
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Shield className="w-5 h-5 mr-2" />
                    Analyze Code
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Results */}
          <div className="space-y-6">
            {results ? (
              <>
                {/* Security Score */}
                <Card className="bg-white/80 backdrop-blur-sm border-gray-200" data-testid="results-card">
                  <CardHeader>
                    <CardTitle style={{ fontFamily: 'Space Grotesk, sans-serif' }}>Security Score</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center justify-between">
                      <div>
                        <div className={`text-5xl font-bold ${getScoreColor(results.security_score)}`}>
                          {results.security_score}
                        </div>
                        <p className="text-sm text-gray-600 mt-1">Out of 100</p>
                      </div>
                      <div className="text-right">
                        <div className="text-2xl font-bold text-gray-900">
                          {results.total_vulnerabilities}
                        </div>
                        <p className="text-sm text-gray-600">Vulnerabilities</p>
                      </div>
                    </div>

                    {/* Severity Counts */}
                    <div className="grid grid-cols-3 gap-2 mt-6">
                      {Object.entries(results.severity_counts).map(([severity, count]) => (
                        count > 0 && (
                          <div key={severity} className="text-center">
                            <Badge className={`${getSeverityColor(severity)} capitalize text-xs`}>
                              {severity}
                            </Badge>
                            <p className="text-lg font-bold text-gray-900 mt-1">{count}</p>
                          </div>
                        )
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* Vulnerabilities List */}
                {results.vulnerabilities.length > 0 ? (
                  <Card className="bg-white/80 backdrop-blur-sm border-gray-200" data-testid="vulnerabilities-list-card">
                    <CardHeader>
                      <CardTitle style={{ fontFamily: 'Space Grotesk, sans-serif' }}>Vulnerabilities Found</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <Accordion type="single" collapsible className="space-y-3">
                        {results.vulnerabilities.map((vuln, index) => (
                          <AccordionItem key={index} value={`item-${index}`} className="border rounded-xl px-4 bg-gray-50">
                            <AccordionTrigger className="hover:no-underline py-4">
                              <div className="flex items-center gap-3 text-left">
                                {getSeverityIcon(vuln.severity)}
                                <div className="flex-1">
                                  <div className="font-semibold text-gray-900">{vuln.title}</div>
                                  <div className="flex items-center gap-2 mt-1">
                                    <Badge className={`${getSeverityColor(vuln.severity)} text-xs capitalize`}>
                                      {vuln.severity}
                                    </Badge>
                                    {vuln.line_number && (
                                      <span className="text-xs text-gray-600">Line {vuln.line_number}</span>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </AccordionTrigger>
                            <AccordionContent className="pb-4 pt-2">
                              <div className="space-y-3 text-sm">
                                <div>
                                  <p className="font-semibold text-gray-700 mb-1">Description:</p>
                                  <p className="text-gray-600">{vuln.description}</p>
                                </div>

                                {vuln.cwe_id && (
                                  <div>
                                    <p className="font-semibold text-gray-700 mb-1">CWE ID:</p>
                                    <Badge variant="outline" className="text-xs">{vuln.cwe_id}</Badge>
                                  </div>
                                )}

                                {vuln.owasp_category && (
                                  <div>
                                    <p className="font-semibold text-gray-700 mb-1">OWASP Category:</p>
                                    <Badge variant="outline" className="text-xs">{vuln.owasp_category}</Badge>
                                  </div>
                                )}

                                {vuln.remediation && (
                                  <div>
                                    <p className="font-semibold text-gray-700 mb-1">How to Fix:</p>
                                    <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                                      <p className="text-gray-700">{vuln.remediation}</p>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </AccordionContent>
                          </AccordionItem>
                        ))}
                      </Accordion>
                    </CardContent>
                  </Card>
                ) : (
                  <Card className="bg-gradient-to-br from-green-50 to-teal-50 border-green-200">
                    <CardContent className="flex flex-col items-center justify-center py-12">
                      <CheckCircle2 className="w-16 h-16 text-green-600 mb-4" />
                      <h3 className="text-xl font-semibold text-gray-900 mb-2">Code Looks Secure!</h3>
                      <p className="text-gray-600 text-center">No vulnerabilities detected in your code.</p>
                    </CardContent>
                  </Card>
                )}
              </>
            ) : (
              <Card className="bg-white/80 backdrop-blur-sm border-gray-200 border-dashed">
                <CardContent className="flex flex-col items-center justify-center py-16">
                  <Shield className="w-16 h-16 text-gray-400 mb-4" />
                  <h3 className="text-lg font-semibold text-gray-700 mb-2">Ready to Analyze</h3>
                  <p className="text-gray-500 text-center max-w-sm">
                    Paste your code and click "Analyze Code" to get instant security insights.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
