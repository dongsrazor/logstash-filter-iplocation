require 'spec_helper'
require "logstash/filters/fsip"

describe LogStash::Filters::Example do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        fsip {
          message => "Hello World"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject).to include("message")
      expect(subject['message']).to eq('Hello World')
    end
  end
end
