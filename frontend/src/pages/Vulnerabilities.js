import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { API } from '../App';
import Navigation from '../components/Navigation';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { AlertTriangle, Shield, Info, FileCode } from 'lucide-react';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '../components/ui/accordion';
import { toast } from 'sonner';

export default function Vulnerabilities({ user }) {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('all');

  useEffect(() => {
    fetchVulnerabilities();
  }, []);

  const fetchVulnerabilities = async () => {
    try {
      const response = await axios.get(`${API}/vulnerabilities`);
      setVulnerabilities(response.data);
    } catch (error) {
      toast.error('Failed to fetch vulnerabilities');
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

  const filteredVulnerabilities = severityFilter === 'all'
    ? vulnerabilities
    : vulnerabilities.filter(v => v.severity === severityFilter);

  const severityCount = {
    all: vulnerabilities.length,
    critical: vulnerabilities.filter(v => v.severity === 'critical').length,
    high: vulnerabilities.filter(v => v.severity === 'high').length,
    medium: vulnerabilities.filter(v => v.severity === 'medium').length,
    low: vulnerabilities.filter(v => v.severity === 'low').length,
    info: vulnerabilities.filter(v => v.severity === 'info').length,
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
        <Navigation user={user} />
        <div className="flex items-center justify-center h-[80vh]">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-blue-50">
      <Navigation user={user} />
      
      <div className="max-w-7xl mx-auto p-6 lg:p-8" data-testid="vulnerabilities-container">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-4xl font-bold text-gray-900 mb-2" style={{ fontFamily: 'Space Grotesk, sans-serif' }}>
            Vulnerabilities
          </h1>
          <p className="text-gray-600">All security findings from your scans</p>
        </div>

        {/* Filters */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2 text-sm text-gray-600">
            <span>Showing {filteredVulnerabilities.length} of {vulnerabilities.length} vulnerabilities</span>
          </div>
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-[200px]" data-testid="severity-filter">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All ({severityCount.all})</SelectItem>
              <SelectItem value="critical">Critical ({severityCount.critical})</SelectItem>
              <SelectItem value="high">High ({severityCount.high})</SelectItem>
              <SelectItem value="medium">Medium ({severityCount.medium})</SelectItem>
              <SelectItem value="low">Low ({severityCount.low})</SelectItem>
              <SelectItem value="info">Info ({severityCount.info})</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Vulnerabilities List */}
        {filteredVulnerabilities.length > 0 ? (
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200" data-testid="vulnerabilities-list">
            <CardContent className="p-6">
              <Accordion type="single" collapsible className="space-y-4">
                {filteredVulnerabilities.map((vuln, index) => (
                  <AccordionItem 
                    key={vuln.id} 
                    value={vuln.id} 
                    className="border rounded-xl px-4 bg-gray-50"
                    data-testid={`vulnerability-${index}`}
                  >
                    <AccordionTrigger className="hover:no-underline py-4">
                      <div className="flex items-center gap-3 text-left w-full">
                        {getSeverityIcon(vuln.severity)}
                        <div className="flex-1">
                          <div className="font-semibold text-gray-900 mb-1">{vuln.title}</div>
                          <div className="flex items-center gap-3 flex-wrap">
                            <Badge className={`${getSeverityColor(vuln.severity)} text-xs capitalize`}>
                              {vuln.severity}
                            </Badge>
                            {vuln.file_path && (
                              <div className="flex items-center gap-1 text-xs text-gray-600">
                                <FileCode className="w-3 h-3" />
                                {vuln.file_path}
                              </div>
                            )}
                            {vuln.line_number && (
                              <span className="text-xs text-gray-600">
                                Line {vuln.line_number}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent className="pb-4 pt-2">
                      <div className="space-y-4 text-sm">
                        {/* Description */}
                        <div>
                          <p className="font-semibold text-gray-700 mb-2">Description:</p>
                          <p className="text-gray-600 leading-relaxed">{vuln.description}</p>
                        </div>

                        {/* Code Snippet */}
                        {vuln.code_snippet && (
                          <div>
                            <p className="font-semibold text-gray-700 mb-2">Code Snippet:</p>
                            <div className="bg-gray-900 text-gray-100 p-3 rounded-lg overflow-x-auto">
                              <pre className="text-xs font-mono">{vuln.code_snippet}</pre>
                            </div>
                          </div>
                        )}

                        {/* Metadata */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
                        </div>

                        {/* Remediation */}
                        {vuln.remediation && (
                          <div>
                            <p className="font-semibold text-gray-700 mb-2">How to Fix:</p>
                            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                              <p className="text-gray-700 leading-relaxed">{vuln.remediation}</p>
                            </div>
                          </div>
                        )}

                        {/* Timestamp */}
                        <div className="text-xs text-gray-500 pt-2 border-t">
                          Found: {new Date(vuln.created_at).toLocaleString()}
                        </div>
                      </div>
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </CardContent>
          </Card>
        ) : (
          <Card className="bg-white/80 backdrop-blur-sm border-gray-200 border-dashed">
            <CardContent className="flex flex-col items-center justify-center py-16">
              <Shield className="w-16 h-16 text-gray-400 mb-4" />
              <h3 className="text-lg font-semibold text-gray-700 mb-2">
                {severityFilter === 'all' ? 'No Vulnerabilities Found' : `No ${severityFilter} Vulnerabilities`}
              </h3>
              <p className="text-gray-500 text-center max-w-sm">
                {severityFilter === 'all'
                  ? 'Run a scan to start detecting security vulnerabilities in your code.'
                  : `No vulnerabilities with ${severityFilter} severity found. Try a different filter.`}
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
