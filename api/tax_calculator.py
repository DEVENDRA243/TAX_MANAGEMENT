def calculate_tax(income, deductions=0, regime='new'):
    """
    Calculate income tax based on Indian tax slabs for FY 2023-24 (example).
    income: annual taxable income after deductions
    deductions: total deductions allowed
    regime: 'new' or 'old' tax regime
    Returns the calculated tax amount.
    """
    taxable_income = max(0, income - deductions)
    tax = 0

    if regime == 'new':
        slabs = [
            (300000, 0.0),
            (600000, 0.05),
            (900000, 0.10),
            (1200000, 0.15),
            (1500000, 0.20),
            (float('inf'), 0.30)
        ]
    elif regime == 'old':
        slabs = [
            (250000, 0.0),
            (500000, 0.05),
            (1000000, 0.20),
            (float('inf'), 0.30)
        ]
    else:
        # Default to new regime if unknown
        slabs = [
            (250000, 0.0),
            (500000, 0.05),
            (750000, 0.10),
            (1000000, 0.15),
            (1250000, 0.20),
            (1500000, 0.25),
            (float('inf'), 0.30)
        ]

    prev_limit = 0
    for limit, rate in slabs:
        if taxable_income > limit:
            tax += (limit - prev_limit) * rate
            prev_limit = limit
        else:
            tax += (taxable_income - prev_limit) * rate
            break

    return round(tax, 2)
