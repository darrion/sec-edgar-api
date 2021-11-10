def main(tickers): 
    from secedgar import filings, FilingType
    my_filings = filings(cik_lookup=tickers,
                        filing_type=FilingType.FILING_4,
                        user_agent="Your name (your email)")
    my_filings.save('../downloads')
    return len(my_filings)

if __name__ == "__main__": 
    import sys 
    tickers = sys.argv[1:]
    main(tickers)